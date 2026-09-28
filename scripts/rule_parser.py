#!/usr/bin/env python3
"""Parse the restricted YAML subset used by rules.yaml and tests/fixtures.yaml.

The skill's rule files intentionally use a uniform layout: two-space indented
scalar keys, two-space list items, and folded plain scalars whose continuation
lines are indented by exactly four spaces. Comments and nested mappings are not
part of the subset. This module supports exactly that layout so the tooling
works without PyYAML; comment lines, mis-indented continuations, and other
deviations raise `RuleFileError` instead of being folded into the previous
field.
"""
from __future__ import annotations

import re
from pathlib import Path

_KEY_RE = re.compile(r"^  ([a-z_]+):(?: (.*))?$")
_ITEM_RE = re.compile(r"^  - (.+)$")
_BLOCK_START_RE = re.compile(r"^- ([a-z_]+): (.*)$")
_CONTINUATION_RE = re.compile(r"^ {4}\S")


class RuleFileError(ValueError):
    """Raised when a rule file does not match the expected restricted layout."""


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_block(block: str) -> dict:
    """Parse one '- key: value' block into a dict with a '_raw' copy."""
    lines = block.splitlines()
    start = _BLOCK_START_RE.match(lines[0]) if lines else None
    if not start:
        raise RuleFileError(f"unrecognized block start: {lines[0]!r}")

    data: dict = {start.group(1): _unquote(start.group(2))}
    lists: dict[str, list[str]] = {}
    current: str | None = None

    for line in lines[1:]:
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            raise RuleFileError(f"comments are not supported: {line!r}")
        key = _KEY_RE.match(line)
        if key:
            current = key.group(1)
            data[current] = _unquote(key.group(2) or "")
            lists.setdefault(current, [])
            continue
        item = _ITEM_RE.match(line)
        if item and current is not None:
            lists[current].append(_unquote(item.group(1)))
            continue
        if current is None:
            raise RuleFileError(f"continuation without a key: {line!r}")
        if not _CONTINUATION_RE.match(line):
            raise RuleFileError(f"continuation lines must use four-space indentation: {line!r}")
        data[current] = f"{data[current]} {line.strip()}".strip()

    for key, values in lists.items():
        if values:
            data[key] = values

    data["_raw"] = block.rstrip() + "\n"
    return data


def load_blocks(path: str | Path, root_key: str) -> tuple[str | None, list[dict]]:
    """Return (version, records) for a file with a 'root_key:' block list."""
    text = Path(path).read_text(encoding="utf-8")
    version_match = re.search(r"(?m)^version:\s*(\S+)\s*$", text)
    version = version_match.group(1) if version_match else None

    marker = re.search(rf"(?m)^{re.escape(root_key)}:\s*$", text)
    if not marker:
        raise RuleFileError(f"missing root key {root_key!r} in {path}")

    body = text[marker.end():]
    blocks = [b for b in re.split(r"(?m)^(?=- )", body) if b.strip()]
    return version, [parse_block(b) for b in blocks]


def load_rules(path: str | Path) -> tuple[str | None, int | None, list[dict]]:
    """Load rules.yaml, returning (version, declared rule_count, rules)."""
    text = Path(path).read_text(encoding="utf-8")
    count_match = re.search(r"(?m)^rule_count:\s*(\d+)\s*$", text)
    declared = int(count_match.group(1)) if count_match else None
    version, records = load_blocks(path, "rules")
    return version, declared, records
