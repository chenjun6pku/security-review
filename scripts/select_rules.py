#!/usr/bin/env python3
"""Select rules from references/rules.yaml without loading the whole file.

Usage:
  python scripts/select_rules.py                          # compact index
  python scripts/select_rules.py --domain SR-AG
  python scripts/select_rules.py --domain SR-NW --lifecycle runtime
  python scripts/select_rules.py --id AG-001 --id AS-005
  python scripts/select_rules.py --tag exfiltration
  python scripts/select_rules.py --all                    # full rule text

Selected rules are printed as YAML blocks so they can be read directly into an
agent context. Prefer filters over --all.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rule_parser import RuleFileError, load_rules  # noqa: E402

RULE_FILE = Path(__file__).resolve().parent.parent / "references" / "rules.yaml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--id", action="append", default=[], help="rule ID (repeatable)")
    parser.add_argument("--domain", action="append", default=[], help="primary domain, e.g. SR-AG (repeatable)")
    parser.add_argument("--lifecycle", action="append", default=[], help="lifecycle or phase mode (repeatable)")
    parser.add_argument("--tag", action="append", default=[], help="tag filter (repeatable, OR within a filter)")
    parser.add_argument("--list", action="store_true", help="compact index of every rule")
    parser.add_argument("--all", action="store_true", help="print every rule in full")
    parser.add_argument("--json", action="store_true", help="emit selected rules as JSON")
    return parser


def matches(rule: dict, args: argparse.Namespace) -> bool:
    if args.id and rule["id"] not in args.id:
        return False
    if args.domain and rule["domain"] not in args.domain:
        return False
    if args.lifecycle and not set(args.lifecycle) & set(rule.get("lifecycle", [])):
        return False
    if args.tag and not set(args.tag) & set(rule.get("tags", [])):
        return False
    return True


def main() -> int:
    args = build_parser().parse_args()
    try:
        version, declared, rules = load_rules(RULE_FILE)
    except RuleFileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    filtered = args.id or args.domain or args.lifecycle or args.tag
    if args.list or not (filtered or args.all):
        print(f"# rules {version} (declared {declared}, parsed {len(rules)})")
        for rule in rules:
            lifecycle = ",".join(rule.get("lifecycle", []))
            print(f"{rule['id']}\t{rule['domain']}\t{lifecycle}\t{rule['title']}")
        return 0

    selected = [rule for rule in rules if matches(rule, args)]
    if not selected:
        print("no rules matched the given filters", file=sys.stderr)
        return 1

    if args.json:
        payload = [{k: v for k, v in rule.items() if k != "_raw"} for rule in selected]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    for rule in selected:
        print(rule["_raw"].rstrip())
    print(f"# selected {len(selected)} of {len(rules)} rules", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
