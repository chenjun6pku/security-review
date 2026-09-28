# Agentic Security Review Model

## Agent system model

Model the agent as:

`untrusted content → context/retrieval → model decision → tool selection → identity/authorization → side effect → observation → memory`

Treat every arrow as a trust boundary.

## Review surfaces

### Input and context

Check repository README, code comments, tests, fixtures, issues, PRs, logs, docs, web content, email, generated content, tool results, and retrieved documents for instructions that could be mistaken for authoritative agent commands.

### Memory

Check:

- persistent memory
- vector/RAG stores
- summaries
- scratchpads persisted across tasks
- user profile/agent policy storage
- memory write authorization
- provenance and expiry
- cross-user/cross-project contamination

### Tools

Check:

- tool name/description/schema trust
- parameter validation
- excessive capabilities
- hidden side effects
- arbitrary shell/filesystem/browser/Git/deployment operations
- tool server origin
- tool version pinning
- output trust
- duplicate/shadowed tools

### Identity and authority

Check:

- user impersonation
- delegated OAuth scopes
- Git identity
- SSH agent
- cloud credentials
- browser sessions
- CI tokens
- service accounts
- token lifetime and rotation
- whether tool permissions exceed user/task scope

### Approval and oversight

Check whether destructive or external side effects require:

- explicit confirmation
- target/resource display
- intent confirmation
- human-readable action summary
- independent policy enforcement
- audit record

Check for command splitting, aliases, encoding tricks, batching, delayed side effects, or tool indirection that can bypass approval gates.

### Output handling

Trace model output and tool output into:

- shell commands
- SQL/NoSQL queries
- HTTP requests
- URLs
- file paths
- code generation/compilation
- Git operations
- deployment manifests
- browser actions
- policy/configuration changes

Any untrusted output entering a dangerous sink without context-specific validation is a finding candidate.

### MCP

Inspect:

- server provenance
- authentication and authorization
- session isolation
- tool scope
- token exposure
- tool poisoning
- context injection
- shadow servers
- dependency/update path
- auditability

### Multi-agent / A2A

Check whether one agent can pass:

- unverified instructions
- credentials
- tool results
- memory entries
- approval assumptions
- identity assertions

to another agent without provenance or authorization checks.

## Agent finding examples

### Indirect prompt injection

`repository content → context → instruction hierarchy violation → tool call → side effect`

### Tool output poisoning

`untrusted tool response → agent context → model decision → high-impact tool`

### Identity abuse

`agent goal hijack → delegated user token → cloud/Git API → unauthorized change`

### Tool shadowing

`duplicate/ambiguous tool → agent selects attacker-controlled implementation → side effect`

### Memory poisoning

`attacker-controlled content → persistent memory → future unrelated task → unsafe action`
