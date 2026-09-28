# Security Review Report

## 1. Executive summary

- Scope:
- Project type:
- Review mode: static / safe dynamic / mixed
- Lifecycle coverage:
- Material findings:
- Material attack chains:
- Important limitations:

## 2. System model

### Components

### Entry points

### Data/assets

### Identities and privileges

### External dependencies/services

### Trust boundaries

## 3. Lifecycle coverage

| Phase | Reviewed | Evidence | Key findings |
|---|---|---|---|
| Acquisition | | | |
| Dependency resolution | | | |
| Install | | | |
| Build | | | |
| Test | | | |
| CI/CD | | | |
| Runtime | | | |
| Update | | | |
| Rollback | | | |
| Uninstall | | | |
| Cleanup | | | |
| Agent-mediated / isolated mode | | | |

## 4. Findings

Use one section per finding following `references/output.md`. A minimal complete
report is in `references/report-example.md`, and `references/finding-example.json`
shows one finding in the machine-readable form defined by
`references/finding-schema.json`. The Markdown report is the primary deliverable;
produce findings JSON in addition only when requested or useful to the consumer.

## 5. Attack chains

For each chain:

`entry → capability → boundary crossing → asset/action → impact`

Explain which findings contribute to each chain.

## 6. Important negative evidence

List meaningful checks performed with no issue found.

## 7. Remediation plan

Group by:

1. immediate containment
2. code/config fix
3. dependency/toolchain fix
4. agent policy/control fix
5. verification/regression testing

## 8. Framework crosswalk

Map material findings to applicable framework identifiers and versions using the
table and versioning rule in `references/framework-crosswalk.md`. Do not invent
requirement mappings.

## 9. Limitations and assumptions

Explicitly identify unavailable source, runtime, registry, deployment, operating-system, cloud, or legal context.
