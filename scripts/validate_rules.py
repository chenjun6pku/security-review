#!/usr/bin/env python3
"""Validate the security-review skill without external dependencies.

Checks:
- rules.yaml parses under the restricted layout and matches rule_count/version
- IDs are unique, well formed, and use the prefix of their primary domain
- required fields are present and non-empty
- lifecycle and tag values come from references/taxonomy.md vocabularies
- every primary domain has at least one rule
- tests/fixtures.yaml provides one true-positive and one near-miss per domain
- SKILL.md frontmatter is well formed, referenced files exist, and every
  references/ file is routed from SKILL.md
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rule_parser import RuleFileError, load_blocks, load_rules  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = ROOT / "references" / "rules.yaml"
TAXONOMY_FILE = ROOT / "references" / "taxonomy.md"
FIXTURES_FILE = ROOT / "tests" / "fixtures.yaml"
SKILL_FILE = ROOT / "SKILL.md"

REQUIRED_RULE_FIELDS = [
    "id", "domain", "title", "lifecycle", "tags",
    "check", "evidence", "escalate_when", "remediation",
]
BEHAVIORS = {
    "benign_or_expected_capability",
    "security_relevant_capability",
    "reachable_security_behavior",
    "suspicious_behavior",
    "confirmed_malicious_behavior",
}


def section(text: str, heading: str) -> str:
    match = re.search(rf"(?ms)^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text)
    return match.group(1) if match else ""


def vocab(text: str, heading: str) -> set[str]:
    tokens = re.findall(r"`([^`]+)`", section(text, heading))
    return {t for t in tokens if "." not in t and "/" not in t and " " not in t}


def main() -> int:
    errors: list[str] = []

    taxonomy = TAXONOMY_FILE.read_text(encoding="utf-8")
    domains = set(re.findall(r"(?m)^\| (SR-[A-Z]{2}) \|", taxonomy))
    if not domains:
        errors.append("taxonomy.md: no primary domains found")

    lifecycle_allowed = vocab(taxonomy, "Lifecycle tags") | vocab(taxonomy, "Rule phase extensions")
    tag_allowed = (
        vocab(taxonomy, "Asset tags")
        | vocab(taxonomy, "Impact tags")
        | vocab(taxonomy, "Behavior tags")
        | vocab(taxonomy, "Exposure tags")
        | vocab(taxonomy, "Rule-level control tags")
    )
    if not lifecycle_allowed:
        errors.append("taxonomy.md: lifecycle vocabulary could not be parsed")
    if not tag_allowed:
        errors.append("taxonomy.md: tag vocabulary could not be parsed")

    skill_text = SKILL_FILE.read_text(encoding="utf-8")
    version_match = re.search(r'(?m)^  version:\s*"?([0-9]+\.[0-9]+\.[0-9]+)"?\s*$', skill_text)
    skill_version = version_match.group(1) if version_match else None
    if not skill_version:
        errors.append("SKILL.md: metadata.version missing or not semver")

    try:
        rules_version, declared_count, rules = load_rules(RULES_FILE)
    except RuleFileError as exc:
        print(f"ERROR: rules.yaml: {exc}")
        return 1

    if rules_version != skill_version:
        errors.append(f"version mismatch: rules.yaml {rules_version} != SKILL.md {skill_version}")
    if declared_count != len(rules):
        errors.append(f"rule_count mismatch: declared {declared_count}, parsed {len(rules)}")

    ids: Counter = Counter()
    titles: Counter = Counter()
    domain_counts: Counter = Counter()
    for rule in rules:
        rid = rule.get("id", "<missing>")
        ids[rid] += 1
        titles[rule.get("title", "")] += 1
        domain = rule.get("domain", "")
        domain_counts[domain] += 1

        for field in REQUIRED_RULE_FIELDS:
            value = rule.get(field)
            if value is None or (isinstance(value, str) and not value.strip()):
                errors.append(f"{rid}: missing or empty field '{field}'")
            elif isinstance(value, list) and not value:
                errors.append(f"{rid}: empty list field '{field}'")

        if not re.fullmatch(r"[A-Z]{2}-\d{3}", rid):
            errors.append(f"{rid}: ID must match ^[A-Z]{{2}}-[0-9]{{3}}$")
        if domain not in domains:
            errors.append(f"{rid}: unknown domain '{domain}'")
        else:
            expected_prefix = domain.split("-", 1)[1]
            if not rid.startswith(expected_prefix + "-"):
                errors.append(f"{rid}: prefix does not match domain {domain}")

        lifecycle = rule.get("lifecycle", [])
        if isinstance(lifecycle, list):
            for value in lifecycle:
                if value not in lifecycle_allowed:
                    errors.append(f"{rid}: lifecycle value '{value}' is not in the taxonomy vocabulary")
        tags = rule.get("tags", [])
        if isinstance(tags, list):
            for value in tags:
                if value not in tag_allowed:
                    errors.append(f"{rid}: tag '{value}' is not in the taxonomy vocabulary")

    for rid, count in ids.items():
        if count > 1:
            errors.append(f"{rid}: duplicate rule ID")
    for title, count in titles.items():
        if count > 1 and title:
            errors.append(f"duplicate rule title: '{title}'")
    for domain in sorted(domains):
        if domain_counts[domain] == 0:
            errors.append(f"{domain}: no rules defined")

    try:
        fixtures_version, fixtures = load_blocks(FIXTURES_FILE, "fixtures")
    except RuleFileError as exc:
        errors.append(f"tests/fixtures.yaml: {exc}")
        fixtures = []

    if fixtures_version != skill_version:
        errors.append(f"fixtures version mismatch: {fixtures_version} != SKILL.md {skill_version}")

    rules_by_id = {rule["id"]: rule for rule in rules}
    fixture_kinds: dict[tuple[str, str], set[str]] = {}
    for fixture in fixtures:
        domain = fixture.get("domain", "")
        rid = fixture.get("rule", "")
        kind = fixture.get("kind", "")
        fixture_kinds.setdefault((domain, rid), set()).add(kind)
        rule = rules_by_id.get(rid)
        if not rule:
            errors.append(f"fixture references unknown rule '{rid}'")
        elif rule.get("domain") != domain:
            errors.append(f"fixture {rid}: domain '{domain}' does not match rule domain '{rule.get('domain')}'")
        if kind not in {"true_positive", "near_miss"}:
            errors.append(f"fixture {rid}: invalid kind '{kind}'")
        if fixture.get("expected_behavior") not in BEHAVIORS:
            errors.append(f"fixture {rid}: invalid expected_behavior '{fixture.get('expected_behavior')}'")
        if not fixture.get("snippet", "").strip():
            errors.append(f"fixture {rid}: empty snippet")

    for domain in sorted(domains):
        kinds = {
            "true_positive": any(d == domain and "true_positive" in k for (d, _), k in fixture_kinds.items()),
            "near_miss": any(d == domain and "near_miss" in k for (d, _), k in fixture_kinds.items()),
        }
        for kind, present in kinds.items():
            if not present:
                errors.append(f"{domain}: missing {kind} fixture")

    frontmatter = re.search(r"(?ms)^---\n(.*?)\n---", skill_text)
    if not frontmatter:
        errors.append("SKILL.md: frontmatter block not found")
    else:
        block = frontmatter.group(1)
        name_match = re.search(r"(?m)^name:\s*(\S+)\s*$", block)
        description_match = re.search(r"(?m)^description:\s*(.+)$", block)
        if not name_match:
            errors.append("SKILL.md: name missing")
        elif not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name_match.group(1)):
            errors.append("SKILL.md: name is not lowercase-hyphenated")
        if not description_match:
            errors.append("SKILL.md: description missing")
        elif len(description_match.group(1)) > 1024:
            errors.append("SKILL.md: description exceeds 1024 characters")

    for referenced in set(re.findall(r"references/([A-Za-z0-9._-]+)", skill_text)):
        if not (ROOT / "references" / referenced).is_file():
            errors.append(f"SKILL.md references missing file: references/{referenced}")
    for referenced in set(re.findall(r"scripts/([A-Za-z0-9_]+\.py)", skill_text)):
        if not (ROOT / "scripts" / referenced).is_file():
            errors.append(f"SKILL.md references missing file: scripts/{referenced}")
    for path in sorted((ROOT / "references").iterdir()):
        if path.is_file() and f"references/{path.name}" not in skill_text:
            errors.append(f"SKILL.md does not route to references/{path.name}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"FAILED: {len(errors)} problem(s)")
        return 1

    print(
        "OK: "
        f"{len(rules)} rules / {len(domains)} domains / {len(fixtures)} fixtures; "
        f"version {skill_version}; vocabulary {len(lifecycle_allowed)} lifecycle values, {len(tag_allowed)} tags"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
