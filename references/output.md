# Output Contract

## Executive summary

Start with:

- scope
- project type
- lifecycle coverage
- top material findings
- major attack chains
- important blind spots

Do not use an overall security score.

## Finding format

```markdown
## [SR-0001] Title

- Severity: High
- Confidence: High
- Behavior: reachable_security_behavior
- Primary domain: SR-SC
- Lifecycle: install, runtime
- Tags: execution, credential-access, exfiltration
- Affected: path/to/file:line

### Risk
<One concise technical statement describing what can happen and to whom/what.>

### Evidence
- `path/to/file:line`: <relevant mechanism>
- <configuration/dependency/runtime evidence>

### Trigger and reachability
<How the path is reached; required user/attacker action; privilege and preconditions.>

### Impact
<Confidentiality / Integrity / Availability / identity / host / cloud impact and blast radius.>

### Attack chain
`entry → capability → boundary → asset/action → impact`

### Why this is / is not malicious
<Describe observed or inferred behavior without guessing intent.>

### Remediation
<Concrete code/config/process change.>

### Validation
<How to verify the fix without exposing secrets or causing harmful side effects.>
```

Finding IDs are sequential per report in `SR-0001` form. `Lifecycle` lists every
applicable phase with the primary phase first, and the remaining fields mirror
`references/finding-schema.json`.

The Markdown report is the primary deliverable. When a machine-readable artifact
is requested or useful, also emit the findings as a JSON array that conforms to
`references/finding-schema.json`; `references/finding-example.json` shows one
complete finding.

## Severity ordering

Within the report, order by severity then confidence then blast radius, but do not create a score or ranking of options.

## “Not found” section

Include only meaningful negative checks, for example:

- no automatic persistence discovered in common OS mechanisms;
- no outbound telemetry destination found after inspecting network clients;
- release integrity verification is present;
- container has no host Docker socket mount.

## Limitations

Always list unavailable evidence and scope gaps. Examples:

- external package registry history not available;
- runtime execution not authorized;
- Windows-specific installer not reviewed on Linux;
- cloud deployment configuration absent from repository.
