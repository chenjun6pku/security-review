#!/usr/bin/env python3
"""Regression tests for the indicator patterns in static_security_scan.py.

Usage: python scripts/run_scan_tests.py

Cases live in tests/scanner_cases.yaml, written in the restricted layout parsed
by scripts/rule_parser.py. Each case asserts that a scanner rule matches or does
not match a sample string, so pattern regressions (for example a trailing `\\b`
that disables an alternative) are caught without executing target project code.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rule_parser import RuleFileError, load_blocks  # noqa: E402
from static_security_scan import RULES  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CASES_FILE = ROOT / "tests" / "scanner_cases.yaml"
EXPECTED = {"match", "no_match"}


def main() -> int:
    try:
        cases_version, cases = load_blocks(CASES_FILE, "cases")
    except RuleFileError as exc:
        print(f"ERROR: {CASES_FILE.name}: {exc}")
        return 2

    patterns = {rule_id: pattern for rule_id, pattern, _ in RULES}
    errors: list[str] = []
    for case in cases:
        rule_id = case.get("rule", "")
        expect = case.get("expect", "")
        sample = case.get("sample", "")
        if rule_id not in patterns:
            errors.append(f"unknown scanner rule '{rule_id}'")
            continue
        if expect not in EXPECTED:
            errors.append(f"{rule_id}: invalid expect value '{expect}'")
            continue
        if not sample:
            errors.append(f"{rule_id}: empty sample")
            continue
        matched = bool(patterns[rule_id].search(sample))
        if matched != (expect == "match"):
            errors.append(f"{rule_id}: expected {expect} for {sample!r}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"FAILED: {len(errors)} case(s)")
        return 1

    print(f"OK: {len(cases)} scanner cases (version {cases_version}, {len(RULES)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
