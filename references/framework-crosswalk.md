# Framework Crosswalk

The Skill uses a practical internal taxonomy and references established frameworks for terminology and control coverage. Framework mappings are references, not claims of formal certification.

| Skill area | Primary references | Use |
|---|---|---|
| Application security | OWASP ASVS 5.0.0; OWASP Top 10 2025 | testable application controls, injection, access control, crypto, integrity, logging, exception handling |
| AI/ML security | OWASP AISVS 1.0 | AI-specific, testable controls across lifecycle; especially orchestration, identity, MCP, memory, monitoring |
| LLM/GenAI | OWASP GenAI LLM Top 10 2026 | current GenAI/LLM risk vocabulary and threat coverage |
| Agentic AI | OWASP Top 10 for Agentic Applications 2026; OWASP Agentic Threats & Mitigations | goal hijack, tool misuse, identity abuse, supply chain, code execution, memory/context and related agent risks |
| MCP | OWASP MCP Top 10 2025; OWASP Secure MCP Server Development guide | token exposure, scope creep, tool poisoning, prompt/context injection, authn/authz, shadow MCP, audit |
| Runtime agent controls | OWASP Agent Control Standard (ACS), 2026 | inspectability, traceability, instrumentation, declarative runtime controls |
| Secure development | NIST SP 800-218 SSDF 1.1 | secure development practices across the software lifecycle |
| Supply chain | SLSA 1.2; OWASP SCVS | provenance, source/build traceability, component assurance |
| Adversarial AI | MITRE ATLAS | techniques such as context/tool poisoning, tool invocation, supply-chain manipulation, evasion |

## Versioning rule

When recording a framework requirement ID, include its version, for example `ASVS-5.0.0-V1.2.x` or `AISVS-1.0-C9.4.3`. Do not cite a requirement without its version.

## Interpretation rule

A framework mapping is supporting evidence. The Skill's finding still needs repository-specific evidence, trigger analysis, impact, and confidence.
