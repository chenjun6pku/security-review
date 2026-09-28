# Assessment Model

## Finding model

Every candidate finding should be modeled as:

`source → control boundary → transformation → sink → consequence`

Also record:

`trigger + preconditions + privilege + reachability + blast radius + persistence`

## Capability versus behavior

### Capability present
The project contains a primitive capable of an action, but no concrete path to a security impact has been established.

### Reachable security behavior
The action is reachable through a normal or plausible trigger and crosses a security boundary.

### Observed behavior
Static analysis or runtime evidence demonstrates the action actually occurs under a tested path.

### Suspicious behavior
Behavior has strong indicators of unauthorized or security-incongruent activity, but intent is not directly established.

### Confirmed malicious behavior
A controlled analysis demonstrates behavior designed to obtain unauthorized control/data, evade oversight, persist, or cause harm. Use only when evidence supports this classification.

## Severity dimensions

Assess separately:

- Impact: what can be compromised?
- Exploitability: how easily can an attacker/user trigger it?
- Exposure: where/when is the path available?
- Privilege: which identity executes the action?
- Persistence: does the effect survive restart/update/uninstall?
- Blast radius: one process, one host, many hosts, organization/cloud?

Do not collapse these dimensions into a single intuition.

## Evidence grading

**E1 — direct evidence**: exact code/config path, runtime event, dependency metadata, or artifact metadata.

**E2 — strong inferred path**: call/data flow is clear, but dynamic evidence is unavailable.

**E3 — weak indicator**: pattern exists but reachability, intent, or impact is uncertain.

**E4 — external dependency uncertainty**: a claim depends on unavailable registry/vendor/service information.

Map E1/E2/E3/E4 to `confirmed/high/medium/low` confidence with care.

## False-positive controls

Before reporting a high-impact finding, verify:

1. the code is in a reachable production/development path;
2. the dangerous operation is not dead code or test-only unless tests are automatically invoked;
3. validation/sanitization does not actually break the suspected path;
4. required permissions are available under the deployment identity;
5. security controls do not block the path;
6. configuration defaults and actual deployment differ only when documented;
7. the impact is not overstated.

## Negative evidence

Record important negative evidence such as:

- no persistence mechanism found after checking common locations;
- no outbound network use observed in static/runtime review;
- secret file paths referenced but never reached from an entry point;
- release signature verification present;
- container lacks Docker socket and host mounts.

Negative evidence is not proof of absence; it means the relevant evidence was checked.
