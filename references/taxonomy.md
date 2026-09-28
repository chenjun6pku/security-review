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

## Issue types

Every reported issue carries exactly one reader-facing type from this closed
vocabulary. JSON output uses the canonical English value (`issue_type`);
localized output uses the localized label.

| Canonical | 中文标签 | Typical primary domains |
|---|---|---|
| memory-safety | 内存安全 | SR-AS, SR-RT |
| injection | 注入与动态执行 | SR-AS |
| authn-authz | 认证与授权缺陷 | SR-AS |
| privilege-escalation | 权限提升 | SR-HP |
| credential-exposure | 凭据泄露 | SR-ID |
| data-privacy | 隐私与数据泄露 | SR-DA |
| information-disclosure | 信息泄露（日志/侧信道） | SR-DA, SR-AS |
| denial-of-service | 拒绝服务 | SR-AS, SR-RT |
| backdoor-covert-channel | 后门与隐蔽通道 | SR-NW, SR-AG |
| supply-chain | 供应链与构建完整性 | SR-SC, SR-BL |
| lifecycle-behavior | 安装/更新/卸载行为 | SR-LC |
| hardening-config | 配置与加固缺失 | SR-HP, SR-BL |
| crypto-protocol | 加密与协议设计 | SR-AS |
| compliance-license | 合规与许可证 | SR-SC |
| agentic-risk | Agent 与工具链风险 | SR-AG |

`backdoor-covert-channel` is reserved for issues whose behavior classification is
`suspicious_behavior` or `confirmed_malicious_behavior`, or whose evidence
otherwise demonstrates covert control or hidden communication. A capability
alone is typed by its effect (for example `injection` or `hardening-config`).

## Asset tags

`source-code`, `artifact`, `credential`, `token`, `key`, `filesystem`, `process`, `memory`, `ipc`, `database`, `browser`, `user-data`, `model`, `memory-store`, `tool`, `mcp-server`, `cloud-resource`, `network-service`, `ci-runner`, `git-repository`

## Impact tags

`confidentiality`, `integrity`, `availability`, `identity-compromise`, `host-compromise`, `cloud-compromise`, `source-compromise`, `supply-chain-compromise`, `financial-abuse`, `privacy`, `ip-license`

## Behavior tags

`execution`, `privilege-escalation`, `credential-access`, `data-access`, `collection`, `exfiltration`, `modification`, `destruction`, `persistence`, `lateral-movement`, `network-discovery`, `resource-abuse`, `evasion`, `anti-analysis`

## Exposure tags

`local`, `local-user-assisted`, `network-facing`, `install-time`, `build-time`, `ci`, `agent-mediated`, `supply-chain`, `containerized`, `sandboxed`

## Rule phase extensions

`rules.yaml` lifecycle values may use the lifecycle tags above plus these review modes when a rule is specifically about an agent-mediated or isolated environment: `agent-mediated`, `containerized`, `sandboxed`. Findings from these rules must still be mapped to the closest real lifecycle phase in reports, with the mode recorded in the report's lifecycle coverage table.

## Rule-level control tags

Rules may use these technique/control tags in addition to the tag vocabularies above: `network`, `injection`, `authorization`, `isolation`.

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
