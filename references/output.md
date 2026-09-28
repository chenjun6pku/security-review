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
## [SR-XXXX] Title

- Severity: High
- Confidence: High
- Behavior: reachable_security_behavior
- Primary domain: SR-XX
- Lifecycle: install
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
