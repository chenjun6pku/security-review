# Remediation Patterns

## Execution

Replace shell interpretation with direct process APIs and structured arguments. Separate untrusted input parsing from command invocation. Avoid executing downloaded content.

## Privilege

Split privileged helpers from untrusted code, authenticate IPC callers, apply least privilege, and eliminate unnecessary admin/root execution.

## Credentials

Use short-lived, scoped credentials; avoid broad environment inheritance; keep secrets outside model-visible content and logs; prefer OS/cloud secret stores.

## Filesystem

Canonicalize paths, enforce root containment, use safe temporary files, reject symlink/TOCTOU hazards, and minimize read/write roots.

## Network

Use explicit egress allow-lists for sensitive workloads, strict TLS validation, authenticated update metadata, and destination validation for user-controlled URLs.

## Supply chain

Pin dependencies and privileged CI actions, verify artifact signatures/digests, retain provenance, isolate build caches, and use ephemeral trusted build environments.

## Containers

Remove Docker socket access, privileged mode, unnecessary capabilities/devices, host mounts/namespaces, and unneeded credentials. Prefer rootless/minimal images where practical.

## Application security

Use ASVS-oriented controls: strict input validation, parameterized queries, correct output encoding, strong authentication and authorization, secure deserialization, safe file handling, robust crypto, and meaningful logging.

## Agentic systems

Treat external content/tool output as untrusted, use explicit provenance, least-privilege delegated identities, schema-constrained tools, policy enforcement outside the model, mandatory approval for high-impact actions, and auditable action logs.

## Privacy

Minimize data collection, purpose-limit processing, disclose external sharing, apply retention limits, and separate technical observations from legal conclusions.
