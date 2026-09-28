# Evidence Collection Guide

## Source evidence

Capture:

- relative file path
- function/class/symbol
- relevant line range
- data/control-flow explanation
- configuration key or environment variable

Never include real secret values.

## Dependency evidence

Capture:

- manifest
- lockfile
- resolved version
- source/registry URL
- integrity field
- lifecycle scripts
- direct/transitive relationship
- update automation

## Build/CI evidence

Inspect:

- Makefile/CMake/Gradle/Maven/MSBuild
- package manager lifecycle hooks
- Git hooks
- CI YAML
- workflow permissions
- runner type
- secrets and OIDC configuration
- artifact upload/download
- cache restore/save
- remote scripts/binaries

## Host evidence

Static evidence can include:

- subprocess/system-call APIs
- service/task registration
- account management APIs
- registry/startup locations
- shell profile modification
- firewall/security-control commands
- privileged Docker APIs
- filesystem write targets

Dynamic evidence, when authorized and isolated, can include:

- process tree
- child commands
- file changes
- sockets/DNS/HTTP metadata
- service/task changes
- mount/capability/device access

## Identity and secret evidence

Look for access to:

- env vars
- config files
- secret managers
- SSH/Git/cloud/Kubernetes credentials
- browser sessions/cookies
- certificate/private-key stores
- CI secret contexts

Report only path/type/metadata unless a synthetic credential is explicitly used in isolation.

## Agent evidence

Capture:

- system/developer/user prompts when in scope
- repository content supplied to context
- retrieval sources
- memory read/write operations
- tool descriptions and schemas
- tool server origin/identity
- delegated credentials/scopes
- approval gates
- tool-call logs
- downstream sinks

Treat tool output and retrieved content as untrusted input by default.

## Network evidence

Capture:

- destination hostname/IP
- protocol/port
- code path creating connection
- frequency/trigger
- request type
- data class sent
- TLS verification behavior

Do not upload or transmit user data to prove a suspected path.

## Artifact evidence

Capture:

- SHA-256 or stronger digest
- signature/attestation presence
- release/tag/commit relationship
- provenance metadata
- build identity
- source/material identifiers
