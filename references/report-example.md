# Minimal Example

## Decision summary (TL;DR)

- Verdict: do not install until the install hook is removed or pinned and verified.
- Highest severity: High; 1 High finding in this excerpt.
- Key risks: installation-time remote code execution from an unpinned download.

## Executive summary

The project has one high-confidence installation-time code execution path and one medium-confidence agentic prompt-injection path. No persistence was found in the reviewed Linux startup locations. Dynamic execution was not performed on the host.

### [SR-0001] Installation hook executes downloaded code

- Severity: High
- Confidence: High
- Behavior: reachable_security_behavior
- Primary domain: SR-SC
- Lifecycle: install
- Tags: execution, supply-chain, network
- Affected: `package.json:12`

### Risk
The package manager executes an install hook that downloads a remote script and executes it with installer privileges.

### Evidence
- `package.json:12`: `postinstall` invokes a shell command.
- `scripts/bootstrap.js:44`: downloads content from a runtime-configurable URL.

### Trigger and reachability
The path runs during a normal dependency installation. No special application runtime input is required.

### Impact
The downloaded code inherits the install user's privileges and can access the local workspace and environment.

### Attack chain
`dependency resolution → postinstall → remote download → shell execution → local environment access`

### Why this is / is not malicious
The hook is reachable on the normal install path and lacks integrity verification. No hidden behavior or intent is claimed; the report classifies it as reachable security behavior rather than maliciousness.

### Remediation
Pin and verify the source, remove runtime code download, or replace the hook with a deterministic local build step.

### Validation
Perform installation in a disposable sandbox with synthetic credentials and blocked outbound access; verify the hook no longer performs remote execution.

See `references/finding-example.json` for one complete finding in the
machine-readable form defined by `references/finding-schema.json`.
