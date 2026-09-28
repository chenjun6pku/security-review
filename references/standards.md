# Standards Baseline

Baseline checked for this Skill design on 2026-09-28.

## Agent Skills

- Agent Skills specification: https://agentskills.io/specification
- OpenAI skill authoring guidance: https://github.com/openai/skills/tree/main/skills/.system/skill-creator
- OpenAI security best-practices skill: https://github.com/openai/skills/tree/main/skills/.curated/security-best-practices
- OpenAI security-threat-model skill: https://github.com/openai/skills/tree/main/skills/.curated/security-threat-model

Use the current Agent Skills structure: required `SKILL.md`; optional `agents/`, `scripts/`, `references/`, and `assets/`. Keep the top-level `SKILL.md` concise and progressively disclose detailed material.

## Application and software security

- OWASP ASVS 5.0.0 (May 2025): https://owasp.org/www-project-application-security-verification-standard
- OWASP Top 10 2025: https://top10.owasp.org/2025/

Use ASVS requirements as testable control anchors rather than treating the Top 10 as an exhaustive test checklist.

## AI / agent security

- OWASP AISVS 1.0 (June 2026): https://owasp.github.io/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/
- OWASP GenAI LLM Top 10 2026 (August 2026): https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- OWASP Top 10 for Agentic Applications 2026: OWASP GenAI Security Project resource hub, https://genai.owasp.org/
- OWASP MCP Top 10 (2025): https://owasp.org/projects/mcp-top-10
- OWASP Agent Control Standard (September 2026): https://genai.owasp.org/resource/agent-control-standard-acs/
- OWASP Secure MCP Server Development guide (February 2026): https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
- MITRE ATLAS: https://atlas.mitre.org/

Use AISVS as the main testable control layer for AI-specific reviews; use agentic Top 10 / LLM Top 10 / MCP Top 10 for threat vocabulary and coverage; use ACS for inspectability, traceability, instrumentation, and runtime control concepts; use ATLAS for adversarial technique mapping.

## Secure development and supply chain

- NIST SP 800-218 SSDF 1.1: https://csrc.nist.gov/pubs/sp/800/218/final
- SLSA 1.2: https://slsa.dev/spec/v1.2/
- SLSA provenance: https://slsa.dev/spec/v1.2/provenance
- OWASP SCVS: https://owasp.org/projects/software-component-verification-standard

Use SSDF for lifecycle/process expectations, SLSA for source/build provenance and artifact traceability, and SCVS for software-component supply-chain assurance.

## Agent standards work

- NIST AI Agent Standards Initiative (announced February 2026), including its software-agent identity and authorization concept work: https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure

Treat these as emerging standards work. Do not claim conformance to draft or initiative materials unless an explicit published requirement supports the claim.

## Update policy

When maintaining the Skill:

1. verify current versions of the standards above;
2. update version labels and crosswalks;
3. add new rules without changing existing IDs' meanings;
4. deprecate rules instead of silently reusing IDs;
5. add a test scenario for material new attack classes;
6. re-verify every link above and prefer stable project hubs over announcement
   or blog deep links, which change without notice;
7. rerun Skill validation and rule/schema checks.
