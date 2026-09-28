# Rule Authoring Standard

## Rule format

Each rule in `references/rules.yaml` uses:

```yaml
- id: AG-004
  domain: SR-AG
  title: Tool output poisoning
  lifecycle:
  - runtime
  - agent-mediated
  tags:
  - execution
  - integrity
  check: What should be inspected
  evidence: What proves or disproves it
  escalate_when: Conditions that materially increase impact
  remediation: Concrete mitigation
```

## File layout

`rules.yaml`, `tests/fixtures.yaml`, and `tests/scanner_cases.yaml` are parsed by
`scripts/rule_parser.py` without PyYAML, so they must use exactly this layout:

- block start `- key: value` at column 0;
- scalar keys indented by exactly two spaces;
- list items written as `- value` indented by two spaces under their key;
- folded continuations indented by exactly four spaces;
- no comments and no nested mappings.

Any other layout raises a parse error during validation instead of being
silently folded into the previous field.

## ID policy

- Prefix with domain catalog: `SC`, `LC`, `BL`, `HP`, `ID`, `DA`, `RT`, `NW`, `AS`, `AG`.
- Use a three-digit numeric suffix.
- Never reuse an ID for a different semantic rule.
- If a rule is split, retire the old ID and create new IDs.

## Allowed vocabularies

Use the canonical vocabularies in `references/taxonomy.md`; do not invent new lifecycle phases or tags.

- `lifecycle` values: the lifecycle tags plus the rule phase extensions (`agent-mediated`, `containerized`, `sandboxed`).
- `tags` values: the asset, impact, behavior, and exposure tag vocabularies plus the rule-level control tags (`network`, `injection`, `authorization`, `isolation`).
- `domain` values and ID prefixes must match the primary domains table.

Run `python scripts/validate_rules.py` after any rule change; it enforces this vocabulary, ID uniqueness, prefix/domain agreement, required fields, rule count, and domain fixture coverage.

## Authoring requirements

Every rule MUST specify:

- a checkable condition;
- expected evidence sources;
- severity escalation conditions;
- actionable remediation;
- relevant lifecycle phase(s).

Prefer rules that correspond to a concrete attack surface or control failure. Avoid vague rules such as `project is unsafe` or `code looks malicious`.

## Pattern versus finding

A rule is a detection hypothesis, not a finding. The agent must validate reachability and impact before reporting a material issue.

Examples:

- `subprocess.run()` is an indicator, not automatically a vulnerability.
- `.env` access is an indicator; unauthorized bulk secret collection is a finding.
- code obfuscation is a suspicion indicator, not proof of malware.
- outbound HTTP is not automatically exfiltration; data flow determines the claim.

## Deduplication

Use one primary domain and secondary tags.

Do not create separate findings for:

- command execution + host control when they are the same path;
- credential access + data exfiltration when one path connects them;
- Docker socket + host takeover when the same evidence establishes one chain.

Create separate findings only when the root causes, remediations, or affected boundaries materially differ.

## Rule testability

Each primary domain MUST have at least one true-positive fixture and one near-miss fixture in `tests/fixtures.yaml`, showing:

- a true positive;
- a near miss / false-positive control;
- expected behavior classification.

A new rule that introduces a materially new attack class MUST add or extend a fixture. `scripts/validate_rules.py` enforces the per-domain fixture baseline.

Indicator patterns in `scripts/static_security_scan.py` are covered by
`python scripts/run_scan_tests.py` with cases in `tests/scanner_cases.yaml`. A
changed or added pattern needs at least one matching and one non-matching case,
because trailing word boundaries and similar regex mistakes fail silently.
