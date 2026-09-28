# Changelog

## 1.1.4 — 2026-09-28

- Output target is now explicit: the issue list is delivered in the conversation by default, and the skill never creates files inside the reviewed repository or its workspace.
- A file is written only when the user asks for one: the named path is used, otherwise a location outside the reviewed project, with the absolute path reported and no silent overwrite of an existing file.
- Validation now uses a temporary file: write the draft, run `validate_report.py`, fix what it reports, deliver the content, and delete the temporary file unless a file was requested. Machine-readable findings follow the same rule.
- Added validation scenario 13 for the output target, and removed the earlier ambiguous "before delivering a file" wording.

## 1.1.3 — 2026-09-28

- The default deliverable is now a security issue list instead of a full report: header (target, review mode, verdict, counts), one summary table per severity group covering every issue, one 8-12 line detail card per issue, and a closing coverage-and-limitations block that must state a limitation.
- Detail cards use nine practical fields: 危险等级 / 置信度 / 触发条件 / 原因 / 危害 / 性质 / 证据 / 修复 / 验证. Attack-chain lines are optional and only used when a path crosses components. Domain, lifecycle, and tags stay in the machine-readable findings JSON.
- `references/report-example.md` is now a complete minimal issue list, and the extended full report (document control, system model, lifecycle table, framework crosswalk, appendices) became an opt-in tier that reuses the issue list as its body.
- `scripts/validate_report.py` was rewritten for the list contract: it checks the header fields, severity tables, one-time coverage of every issue ID, declared-versus-actual counts, card fields, sequential IDs, and the mandatory limitation line.
- Added validation scenarios 11 (issue list and language) and 12 (full report on request).

## 1.1.2 — 2026-09-28

- Added an output language policy: human-readable report text follows the user's language, machine-readable tokens stay canonical English, and a report must use exactly one language profile. The terminology table lives in `references/output.md`.
- Every report now opens with a localized decision summary (TL;DR) of 3-6 bullets: verdict, highest severity, top risks, fixability, and the key limitation. A decision verdict is expected; a numeric score is still forbidden.
- Both contract files were localized: `references/output.md` carries the bilingual finding template, and `references/report-template.md` shows the summary block plus bilingual section and table headings.
- Added `scripts/validate_report.py`, which enforces the single language profile, the summary block, the nine report sections, sequential finding IDs, required finding sections, and canonical enum values. CI validates `references/report-example.md`; full reports produced for local testing are not tracked.
- `references/report-example.md` now conforms to the contract, including the decision summary, the maliciousness section, and the `### [SR-0001]` finding heading.
- Added validation scenario 11 for language, decision summary, and per-finding completeness.

## 1.1.1 — 2026-09-28

Review fixes from a static review plus an independent forward test:

- Fixed indicator regexes in `scripts/static_security_scan.py` that silently failed to match `curl -fsSL …`, `fetch("…")`, `require("…")`, and Node `execSync`/destructured child-process calls; added a download-and-execute pipeline rule and a shared cache/virtualenv ignore set.
- Added `scripts/run_scan_tests.py` with `tests/scanner_cases.yaml` so indicator patterns carry matching and non-matching regression cases; CI runs them.
- Replaced the truncating `rg -A 8` fallback in `SKILL.md` with a block-safe command.
- Fixed dead standards links by pointing at stable project hubs and added link re-verification to the maintenance policy.
- Clarified the report contract: the Markdown report is primary, findings JSON is optional and must follow `references/finding-schema.json`; added `references/finding-example.json` and aligned `output.md`, `report-template.md`, and `report-example.md`.
- Routed previously unreferenced references (`assessment.md`, `evidence.md`, `remediation.md`, `report-example.md`, `framework-crosswalk.md`) from `SKILL.md`; `validate_rules.py` now fails when a `references/` file is not routed.
- `rule_parser.py` now rejects comments and mis-indented continuation lines instead of folding them into the previous field; `rule-authoring.md` documents the restricted layout and the scanner regression requirement.
- Added BL-012 (test environment shares production credentials or data) and ID-011 (long-lived credentials baked into deployment configuration or images) with fixtures; the rule set is now 112 rules.
- `project_facts.py` reports manifest ecosystems and skips cache/virtualenv directories; the skill description was tightened and CI pins `actions/checkout` to a commit SHA.

## 1.1.0 — 2026-09-28

- Completed `references/rules.yaml` to 110 rules across all 10 primary domains, adding test-phase execution (BL-011) and agent auditability/runtime control (AG-016).
- Added `scripts/select_rules.py` and a SKILL.md rule-selection protocol so reviews load only relevant rules instead of the full 48 KB rule file.
- Added `scripts/validate_rules.py` with vocabulary, ID, count, fixture, and metadata checks, plus a read-only CI workflow.
- Extended `references/taxonomy.md` with rule phase extensions and rule-level control tags; aligned `rule-authoring.md` and `report-template.md`.
- Added `tests/fixtures.yaml` with true-positive and near-miss fixtures for every primary domain.
- Fixed `scripts/project_facts.py` wildcard manifest detection for `*.csproj` and `*.fsproj`.
