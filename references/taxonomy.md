# Security Review Taxonomy

## Design

Use one primary domain per finding. Use lifecycle, asset, impact, behavior, exposure, environment, and framework labels as orthogonal tags. Do not promote every tag into a top-level category.

## Primary domains

| ID | Domain | Scope |
|---|---|---|
| SR-SC | Supply Chain & Artifact Trust | source provenance, dependencies, registries, releases, images, generated artifacts |
| SR-LC | Lifecycle Operations | acquisition, install, update, rollback, uninstall, cleanup |
| SR-BL | Build & Developer Toolchain | build scripts, hooks, CI/CD, runners, caches, generators, compiler/tool trust |
| SR-HP | Host Execution & Privilege | command execution, privilege, accounts, services, persistence, system modification |
| SR-ID | Identity & Secrets | credentials, tokens, keys, delegated identity, secret stores |
| SR-DA | Data Access & Privacy | filesystem, browser, database, clipboard, screen, user data, telemetry, privacy |
| SR-RT | Runtime, IPC & Isolation | process/memory/IPC, localhost APIs, sandbox/container/VM boundaries, devices |
| SR-NW | Network & External Interaction | inbound/outbound network, exfiltration, C2, scanning, lateral movement, TLS |
| SR-AS | Application & Protocol Security | injection, authn/authz, parser, protocol, memory safety, business logic, crypto |
| SR-AG | Agentic Coding & AI Security | prompt/context/memory/tool/identity/MCP/A2A/agent workflow risks |

## Lifecycle tags

`acquisition`, `dependency-resolution`, `install`, `build`, `test`, `ci`, `runtime`, `deploy`, `update`, `rollback`, `uninstall`, `cleanup`

## Asset tags

`source-code`, `artifact`, `credential`, `token`, `key`, `filesystem`, `process`, `memory`, `ipc`, `database`, `browser`, `user-data`, `model`, `memory-store`, `tool`, `mcp-server`, `cloud-resource`, `network-service`, `ci-runner`, `git-repository`

## Impact tags

`confidentiality`, `integrity`, `availability`, `identity-compromise`, `host-compromise`, `cloud-compromise`, `source-compromise`, `supply-chain-compromise`, `financial-abuse`, `privacy`, `ip-license`

## Behavior tags

`execution`, `privilege-escalation`, `credential-access`, `data-access`, `collection`, `exfiltration`, `modification`, `destruction`, `persistence`, `lateral-movement`, `network-discovery`, `resource-abuse`, `evasion`, `anti-analysis`

## Exposure tags

`local`, `local-user-assisted`, `network-facing`, `install-time`, `build-time`, `ci`, `agent-mediated`, `supply-chain`, `containerized`, `sandboxed`

## Trust-boundary classes

1. `untrusted-content → agent-context`
2. `agent-context → tool-invocation`
3. `tool → resource`
4. `developer → build-system`
5. `repository → dependency-manager`
6. `source → build-artifact`
7. `artifact → installer/updater`
8. `container → host`
9. `process → process/ipc`
10. `application → internal-network`
11. `local-identity → cloud/service`
12. `agent → delegated-identity`

## Primary-domain selection

Choose the domain representing the root cause or main control boundary. Use secondary tags for effects.

Examples:

- Malicious package `postinstall` reading `AWS_ACCESS_KEY_ID`: primary `SR-SC`; tags `execution`, `credential-access`, `exfiltration`.
- Docker socket mounted into a service container: primary `SR-RT`; tags `host-compromise`, `privilege-escalation`.
- README prompt that causes an agent to invoke shell and read `.env`: primary `SR-AG`; tags `credential-access`, `execution`, `exfiltration`.
- SSRF that reaches cloud metadata: primary `SR-AS`; tags `network-discovery`, `credential-access`.
- Auto-update from mutable unverified URL: primary `SR-LC` when the lifecycle mechanism is the root issue; add `supply-chain` tags.

## Non-security analytical dimensions

Do not treat these as primary domains:

- severity
- confidence
- behavior classification
- maliciousness/suspicion
- framework mappings
- remediation status

These are properties of findings.
