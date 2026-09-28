#!/usr/bin/env python3
"""Validate a security issue list against references/output.md.

Usage:
  python scripts/validate_report.py FILE.md [--lang zh|en|auto] [--findings-only]

Checks:
- one language profile is used consistently
- the header carries target, review mode, verdict, and summary counts
- every issue appears exactly once in a severity summary table
- the declared counts match the tables and the detail cards
- each detail card carries the nine required fields
- issue IDs are sequential from SR-0001
- the file ends with a coverage-and-limitations block that states a limitation

Exit codes: 0 valid, 1 problems found, 2 usage or unreadable input.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PROFILES = {
    "zh": {
        "header": {
            "target": "审查对象",
            "mode": "审查方式",
            "verdict": "结论",
            "counts": "统计",
        },
        "sections": ["问题详情", "覆盖与限制"],
        "groups": [
            ("高危", ["High"]),
            ("中危", ["Medium"]),
            ("低危", ["Low", "Informational"]),
            ("信息", ["Informational"]),
        ],
        "fields": {
            "level": "危险等级",
            "confidence": "置信度",
            "trigger": "触发条件",
            "cause": "原因",
            "impact": "危害",
            "nature": "性质",
            "evidence": "证据",
            "fix": "修复",
            "verification": "验证",
        },
        "levels": {"高": "High", "中": "Medium", "低": "Low", "信息": "Informational"},
        "count_keys": {"高危": "High", "中危": "Medium", "低危": "Low", "信息": "Informational"},
        "finding": re.compile(r"^###\s+问题\s*\d+\s*[（(]\s*SR-(\d{4})\s*[）)]", re.M),
        "limitation": "限制",
        "low_keys": ["低危", "信息"],
    },
    "en": {
        "header": {
            "target": "Target",
            "mode": "Review mode",
            "verdict": "Verdict",
            "counts": "Summary counts",
        },
        "sections": ["Issue details", "Coverage and limitations"],
        "groups": [
            ("High", ["High"]),
            ("Medium", ["Medium"]),
            ("Low", ["Low", "Informational"]),
            ("Informational", ["Informational"]),
        ],
        "fields": {
            "level": "Risk level",
            "confidence": "Confidence",
            "trigger": "Trigger",
            "cause": "Root cause",
            "impact": "Impact",
            "nature": "Nature",
            "evidence": "Evidence",
            "fix": "Fix",
            "verification": "Verification",
        },
        "levels": {"High": "High", "Medium": "Medium", "Low": "Low", "Informational": "Informational"},
        "count_keys": {"High": "High", "Medium": "Medium", "Low": "Low", "Informational": "Informational"},
        "finding": re.compile(r"^###\s+Issue\s*\d+\s*[（(]\s*SR-(\d{4})\s*[）)]", re.M),
        "limitation": "Limitation",
        "low_keys": ["Low", "Informational"],
    },
}

TABLE_ROW = re.compile(r"^\|\s*(SR-\d{4})\s*\|", re.M)
HEADING = re.compile(r"^##\s*(?:\d+[.、)]?\s*)?(.+?)\s*$", re.M)
NORMALIZE_RE = re.compile(r"[\s的（）()、:：/]+")


def normalize(text: str) -> str:
    return NORMALIZE_RE.sub("", text)


def field_value(body: str, label: str) -> str | None:
    match = re.search(rf"(?m)^-\s*{re.escape(label)}\s*[:：]\s*(.+?)\s*$", body)
    return match.group(1) if match else None


def count_profile_hits(text: str, profile: dict) -> int:
    hits = 0
    for label in profile["fields"].values():
        hits += len(re.findall(rf"(?m)^-\s*{re.escape(label)}\s*[:：]", text))
    for name in profile["sections"]:
        hits += len(re.findall(rf"(?m)^##\s*(?:\d+[.、)]?\s*)?{re.escape(name)}", text))
    return hits


def group_of_heading(title: str, profile: dict) -> str | None:
    normalized = normalize(title)
    for key, _levels in sorted(profile["groups"], key=lambda item: -len(item[0])):
        if normalized.startswith(normalize(key)):
            return key
    return None


def parse_groups(text: str, profile: dict) -> dict[str, list[str]]:
    """Map group heading -> issue IDs listed under it."""
    groups: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        heading = re.match(r"^##\s*(?:\d+[.、)]?\s*)?(.+?)\s*$", line)
        if heading:
            current = group_of_heading(heading.group(1), profile)
            if current:
                groups.setdefault(current, [])
            continue
        if current:
            row = re.match(r"^\|\s*(SR-\d{4})\s*\|", line)
            if row:
                groups[current].append(row.group(1))
    return groups


def split_cards(text: str, profile: dict) -> list[tuple[str, str]]:
    matches = list(profile["finding"].finditer(text))
    cards = []
    for index, match in enumerate(matches):
        ends = [len(text)]
        if index + 1 < len(matches):
            ends.append(matches[index + 1].start())
        cards.append((match.group(1), text[match.start():min(ends)]))
    return cards


def parse_counts(text: str, profile: dict) -> dict[str, int]:
    line = ""
    counts_label = profile["header"]["counts"]
    for candidate in text.splitlines():
        if re.match(rf"^-\s*{re.escape(counts_label)}\s*[:：]", candidate):
            line = candidate
            break
    declared: dict[str, int] = {}
    for key, level in profile["count_keys"].items():
        match = re.search(rf"{re.escape(key)}\s*(\d+)", line)
        if match:
            declared[level] = int(match.group(1))
    return declared


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", help="path to the issue list (or a findings fragment)")
    parser.add_argument("--lang", choices=["auto", "zh", "en"], default="auto", help="language profile (default: auto)")
    parser.add_argument("--findings-only", action="store_true", help="validate a fragment that has cards but no summary tables")
    args = parser.parse_args()

    path = Path(args.report)
    if not path.is_file():
        print(f"ERROR: not a readable file: {path}")
        return 2
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []

    hits = {name: count_profile_hits(text, profile) for name, profile in PROFILES.items()}
    if args.lang == "auto":
        lang = max(hits, key=lambda name: hits[name])
        if hits[lang] == 0:
            errors.append("no localized issue fields found; expected the zh or en profile from references/output.md")
    else:
        lang = args.lang
    profile = PROFILES[lang]
    other = "en" if lang == "zh" else "zh"
    if hits[other]:
        errors.append(
            f"mixed language profiles: {lang} profile selected ({hits[lang]} matches) "
            f"but the {other} profile also appears {hits[other]} time(s)"
        )

    cards = split_cards(text, profile)
    if not cards:
        errors.append("no issue cards found; expected headings like '### 问题 1（SR-0001）：...' or '### Issue 1 (SR-0001): ...'")
    numbers: list[int] = []
    card_levels: dict[str, str] = {}
    for number, body in cards:
        numbers.append(int(number))
        prefix = f"SR-{number}"
        for key, label in profile["fields"].items():
            value = field_value(body, label)
            if not value:
                errors.append(f"{prefix}: missing or empty field '{label}'")
        level_value = field_value(body, profile["fields"]["level"])
        if level_value:
            token = level_value.split("（")[0].split("(")[0].strip()
            level = profile["levels"].get(token)
            if not level:
                errors.append(f"{prefix}: '{profile['fields']['level']}' value '{token}' is not one of {', '.join(profile['levels'])}")
            else:
                card_levels[f"SR-{number}"] = level
    if numbers and numbers != list(range(1, len(numbers) + 1)):
        errors.append(f"issue IDs must be sequential from SR-0001; found {numbers}")

    if not args.findings_only:
        for label in profile["header"].values():
            if not re.search(rf"(?m)^-\s*{re.escape(label)}\s*[:：]\s*\S", text):
                errors.append(f"missing or empty header line '{label}'")
        for name in profile["sections"]:
            if not re.search(rf"(?m)^##\s*(?:\d+[.、)]?\s*)?{re.escape(name)}", text):
                errors.append(f"missing section '## {name}'")

        groups = parse_groups(text, profile)
        if not groups:
            errors.append("no severity summary tables found")
        seen: dict[str, str] = {}
        for group, ids in groups.items():
            for issue_id in ids:
                if issue_id in seen:
                    errors.append(f"{issue_id} appears more than once in the summary tables")
                seen[issue_id] = group
        for number, _body in cards:
            issue_id = f"SR-{number}"
            if issue_id not in seen:
                errors.append(f"{issue_id}: missing from the severity summary tables")
                continue
            group_levels = dict(profile["groups"]).get(seen[issue_id], [])
            if card_levels.get(issue_id) and card_levels[issue_id] not in group_levels:
                errors.append(
                    f"{issue_id}: card level {card_levels[issue_id]} does not match summary group '{seen[issue_id]}'"
                )

        declared = parse_counts(text, profile)
        actual = {
            "High": sum(len(ids) for group, ids in groups.items() if "High" in dict(profile["groups"])[group]),
            "Medium": sum(len(ids) for group, ids in groups.items() if "Medium" in dict(profile["groups"])[group]),
            "Low+Information": sum(
                len(ids) for group, ids in groups.items() if {"Low", "Informational"} & set(dict(profile["groups"])[group])
            ),
        }
        if declared:
            if declared.get("High", 0) != actual["High"]:
                errors.append(f"declared High count {declared.get('High', 0)} does not match {actual['High']} summary rows")
            if declared.get("Medium", 0) != actual["Medium"]:
                errors.append(f"declared Medium count {declared.get('Medium', 0)} does not match {actual['Medium']} summary rows")
            declared_low = declared.get("Low", 0) + declared.get("Informational", 0)
            if declared_low != actual["Low+Information"]:
                errors.append(
                    f"declared Low+Informational count {declared_low} does not match {actual['Low+Information']} summary rows"
                )
        else:
            errors.append(f"summary counts line '{profile['header']['counts']}' could not be parsed")

        limitations = re.findall(rf"(?m)^-\s*{re.escape(profile['limitation'])}\s*[:：]\s*\S", text)
        if not limitations:
            errors.append(f"coverage-and-limitations block must state a '{profile['limitation']}' item")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"FAILED: {len(errors)} problem(s) in {path.name}")
        return 1

    scope = "findings-only" if args.findings_only else "issue list"
    print(f"OK: {path.name}: {len(cards)} issues, {lang} profile, {scope} structure valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
