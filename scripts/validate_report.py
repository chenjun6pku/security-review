#!/usr/bin/env python3
"""Validate a security review report against references/output.md.

Usage:
  python scripts/validate_report.py REPORT.md [--lang zh|en|auto] [--findings-only]

Checks:
- one language profile is used consistently (localized headings and labels)
- the decision summary carries 3-6 bullets
- the nine report sections are present
- finding IDs are sequential from SR-0001
- every finding carries the required field labels and sections
- severity, confidence, behavior, and domain values are canonical

Exit codes: 0 valid, 1 problems found, 2 usage or unreadable input.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ENUMS = {
    "severity": ["Critical", "High", "Medium", "Low", "Informational"],
    "confidence": ["Confirmed", "High", "Medium", "Low"],
    "behavior": [
        "benign_or_expected_capability",
        "security_relevant_capability",
        "reachable_security_behavior",
        "suspicious_behavior",
        "confirmed_malicious_behavior",
    ],
}

PROFILES = {
    "zh": {
        "summary": "结论摘要",
        "sections": [
            "执行摘要", "系统模型", "生命周期覆盖", "发现", "攻击链",
            "重要负向证据", "修复计划", "框架对照", "局限与假设",
        ],
        "fields": {
            "severity": "严重度",
            "confidence": "置信度",
            "behavior": "行为分类",
            "domain": "主域",
            "lifecycle": "生命周期",
            "tags": "标签",
            "affected": "受影响位置",
        },
        "blocks": {
            "risk": "风险",
            "evidence": "证据",
            "trigger": "触发与可达性",
            "impact": "影响",
            "attack_chain": "攻击链",
            "maliciousness": "恶意性判断",
            "remediation": "修复建议",
            "validation": "验证方法",
        },
    },
    "en": {
        "summary": "Decision summary",
        "sections": [
            "Executive summary", "System model", "Lifecycle coverage", "Findings",
            "Attack chains", "Important negative evidence", "Remediation plan",
            "Framework crosswalk", "Limitations and assumptions",
        ],
        "fields": {
            "severity": "Severity",
            "confidence": "Confidence",
            "behavior": "Behavior",
            "domain": "Primary domain",
            "lifecycle": "Lifecycle",
            "tags": "Tags",
            "affected": "Affected",
        },
        "blocks": {
            "risk": "Risk",
            "evidence": "Evidence",
            "trigger": "Trigger and reachability",
            "impact": "Impact",
            "attack_chain": "Attack chain",
            "maliciousness": "Why this is / is not malicious",
            "remediation": "Remediation",
            "validation": "Validation",
        },
    },
}

FINDING_RE = re.compile(r"^###\s*\[SR-(\d{4})\]", re.M)
DOMAIN_RE = re.compile(r"^SR-[A-Z]{2}$")
NORMALIZE_RE = re.compile(r"[\s的（）()、:：]+")


def normalize(text: str) -> str:
    return NORMALIZE_RE.sub("", text)


def heading_title(line: str) -> str | None:
    match = re.match(r"^##\s*(?:\d+[.、)]?\s*)?(.*?)\s*$", line)
    return match.group(1) if match else None


def count_hits(text: str, profile: dict) -> int:
    hits = 0
    for label in profile["fields"].values():
        hits += len(re.findall(rf"(?m)^-\s*{re.escape(label)}\s*[:：]", text))
    for label in profile["blocks"].values():
        hits += len(re.findall(rf"(?m)^###\s*{re.escape(label)}\s*$", text))
    return hits


def field_value(body: str, label: str) -> str | None:
    match = re.search(rf"(?m)^-\s*{re.escape(label)}\s*[:：]\s*(.+?)\s*$", body)
    return match.group(1) if match else None


def block_present(body: str, label: str) -> bool:
    return re.search(rf"(?m)^###\s*{re.escape(label)}\s*$", body) is not None


def split_findings(text: str) -> list[tuple[str, str]]:
    matches = list(FINDING_RE.finditer(text))
    findings = []
    for index, match in enumerate(matches):
        ends = [len(text)]
        if index + 1 < len(matches):
            ends.append(matches[index + 1].start())
        next_section = re.search(r"(?m)^##\s", text[match.end():])
        if next_section:
            ends.append(match.end() + next_section.start())
        findings.append((match.group(1), text[match.start():min(ends)]))
    return findings


def summary_bullets(lines: list[str], summary_name: str) -> int | None:
    for index, line in enumerate(lines):
        title = heading_title(line)
        if not title or normalize(summary_name) not in normalize(title):
            continue
        bullets = 0
        for following in lines[index + 1:]:
            if following.startswith("## "):
                break
            if re.match(r"^-\s+\S", following):
                bullets += 1
        return bullets
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", help="path to the Markdown report (or finding fragment)")
    parser.add_argument("--lang", choices=["auto", "zh", "en"], default="auto", help="language profile (default: auto)")
    parser.add_argument("--findings-only", action="store_true", help="validate a fragment that has findings but no full report skeleton")
    args = parser.parse_args()

    path = Path(args.report)
    if not path.is_file():
        print(f"ERROR: not a readable file: {path}")
        return 2
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    errors: list[str] = []

    hits = {name: count_hits(text, profile) for name, profile in PROFILES.items()}
    if args.lang == "auto":
        lang = max(hits, key=lambda name: hits[name])
        if hits[lang] == 0:
            errors.append("no localized finding labels found; expected the zh or en profile from references/output.md")
    else:
        lang = args.lang
    profile = PROFILES[lang]
    other_name = "en" if lang == "zh" else "zh"
    if hits[other_name]:
        errors.append(
            f"mixed language profiles: {lang} profile selected ({hits[lang]} matches) "
            f"but the {other_name} profile also appears {hits[other_name]} time(s)"
        )

    findings = split_findings(text)
    if not findings:
        errors.append("no findings found; expected headings like '### [SR-0001] ...' or '### [SR-0001] Title'")
    numbers: list[int] = []
    for number, body in findings:
        numbers.append(int(number))
        prefix = f"SR-{number}"
        for key, label in profile["fields"].items():
            value = field_value(body, label)
            if not value:
                errors.append(f"{prefix}: missing or empty field '{label}'")
                continue
            if key in ENUMS:
                token = value.split("（")[0].split("(")[0].strip()
                if token not in ENUMS[key]:
                    errors.append(f"{prefix}: '{label}' value '{token}' is not one of {', '.join(ENUMS[key])}")
            elif key == "domain" and not DOMAIN_RE.match(value.strip()):
                errors.append(f"{prefix}: '{label}' value '{value}' is not an SR-XX domain")
        for label in profile["blocks"].values():
            if not block_present(body, label):
                errors.append(f"{prefix}: missing section '### {label}'")
    if numbers and numbers != list(range(1, len(numbers) + 1)):
        errors.append(f"finding IDs must be sequential from SR-0001; found {numbers}")

    if not args.findings_only:
        bullets = summary_bullets(lines, profile["summary"])
        if bullets is None:
            errors.append(f"missing decision summary section '## {profile['summary']}'")
        elif not 3 <= bullets <= 6:
            errors.append(f"decision summary must carry 3-6 bullets; found {bullets}")
        for name in profile["sections"]:
            present = any(
                title and normalize(name) in normalize(title)
                for title in (heading_title(line) for line in lines)
            )
            if not present:
                errors.append(f"missing report section '{name}'")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"FAILED: {len(errors)} problem(s) in {path.name}")
        return 1

    scope = "findings-only" if args.findings_only else "report"
    print(f"OK: {path.name}: {len(findings)} findings, {lang} profile, {scope} structure valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
