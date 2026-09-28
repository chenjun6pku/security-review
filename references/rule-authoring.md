# Rule Authoring Standard

## Rule format

Each rule in `references/rules.yaml` uses:

```yaml
- id: AG-004
  domain: SR-AG
  title: Tool output poisoning
  lifecycle: [agent-mediated]
  tags: [execution, integrity]
  check: "What should be inspected"
  evidence: "What proves or disproves it"
  escalate_when: "Conditions that materially increase impact"
  remediation: "Concrete mitigation"
```

## ID policy

- Prefix with domain catalog: `SC`, `LC`, `BL`, `HP`, `ID`, `DA`, `RT`, `NW`, `AS`, `AG`.
- Use a three-digit numeric suffix.
- Never reuse an ID for a different semantic rule.
- If a rule is split, retire the old ID and create new IDs.

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

A new rule should have at least one fixture in `tests/` or an equivalent controlled example showing:

- a true positive;
- a near miss / false-positive control;
- expected evidence;
- expected behavior classification.
