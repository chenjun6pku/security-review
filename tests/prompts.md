# Validation Scenarios

Use these scenarios to test the Skill. The assertions describe expected coverage, not exact wording.

## 1. Malicious install hook

Prompt: "Review this npm package before installation."

Expected:
- inspect package lifecycle scripts and lockfile;
- do not run `npm install` on the host;
- identify remote download/execute paths;
- distinguish capability from observed behavior;
- produce evidence-backed severity/confidence.

## 2. Agent repository prompt injection

Prompt: "Audit this agent repository for indirect prompt injection."

Expected:
- inspect README/docs/comments/tests/fixtures and context assembly;
- identify tool calls that can be induced;
- trace prompt → tool → side effect;
- inspect approval and secret boundaries.

## 3. MCP server

Prompt: "Security review this MCP server before I allow it on my laptop."

Expected:
- inspect server provenance and command line;
- tool scope and authorization;
- token exposure;
- tool/schema poisoning and shadow server possibilities;
- filesystem/network/host privileges.

## 4. CI compromise

Prompt: "Audit the GitHub Actions workflows for supply-chain risks."

Expected:
- inspect workflow triggers, permissions, forks, secrets, runners, action pinning, caches, downloads, artifact provenance;
- identify self-hosted-runner trust boundaries.

## 5. Desktop updater

Prompt: "Review the installer and auto-update system."

Expected:
- inspect install/update/uninstall phases;
- update authenticity, rollback, privileged helper, persistence cleanup;
- avoid executing the updater on the host.

## 6. Web service

Prompt: "Perform an application security review."

Expected:
- ASVS-oriented coverage of authn/authz, injection, file handling, SSRF, crypto, logging, exception handling, business logic;
- source-to-sink evidence.

## 7. Containerized developer tool

Prompt: "Can this containerized coding agent take over the host?"

Expected:
- inspect privileged mode, Docker socket, mounts, namespaces, capabilities, devices, SSH/cloud credentials;
- produce a host-boundary attack chain where evidence supports it.

## 8. Credential discovery utility

Prompt: "Review this developer utility for credential harvesting."

Expected:
- inspect env, SSH, cloud, kube, Git, browser, key/cert stores;
- report broad scanning separately from confirmed exfiltration.

## 9. Update rollback

Prompt: "Audit version rollback and downgrade behavior."

Expected:
- inspect minimum-version enforcement and signed metadata;
- distinguish operational rollback from security-control bypass.

## 10. Uninstall persistence

Prompt: "Check whether uninstall fully removes the application."

Expected:
- inspect services/tasks/startup entries/agents/hooks/temp state;
- identify persistence surviving uninstall.

## 11. Output language and issue list

Prompt: "用中文对这个小工具做一次安全评估，并给出是否可以在生产环境使用的结论。"

Expected:
- only the issue list is produced: header, severity-grouped summary tables, one
  detail card per issue, and a closing 覆盖与限制 block;
- the text is written in Chinese, with only machine-readable tokens left in English
  (issue IDs, paths, commands, identifiers);
- headings and field labels use the Chinese profile from `references/output.md`,
  with no unlocalized headings or labels mixed in;
- the summary tables cover every issue exactly once and the declared counts match
  the tables and cards;
- every issue carries exactly one type from the vocabulary in `references/taxonomy.md`,
  the summary 类型 cell matches the card, and 后门与隐蔽通道 is only used with
  suspicious or confirmed-malicious evidence;
- every card carries the ten fields (危险等级/问题类型/置信度/触发条件/原因/危害/性质/证据/修复/验证)
  in roughly 8-14 lines, without repeating the summary or adding extra sections;
- the closing block states coverage, negative checks, and a limitation;
- `python scripts/validate_report.py <file>` passes.

## 12. Full report on request

Prompt: "给我一份可以提交审计的完整安全报告。"

Expected:
- the issue list stays the body of the report;
- document control and authorization/scope are added;
- appendices add the system model, lifecycle coverage, extended negative evidence,
  framework crosswalk with versions, and limitations;
- no content is duplicated between the body and the appendices.

## 13. Output target

Prompt: "帮我审查这个仓库的安全性。"（未要求保存文件）

Expected:
- the issue list is delivered in the conversation;
- no file is created inside the reviewed repository or its workspace;
- validation uses a temporary file that is removed afterwards;
- when the user then asks "保存到文件" without naming a path, the file is written
  outside the reviewed project, the absolute path is reported, and an existing
  file is not overwritten without confirmation.
