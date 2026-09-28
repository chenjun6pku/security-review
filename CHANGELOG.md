# Changelog

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
