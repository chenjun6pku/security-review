# Output Contract

The default deliverable is a **security issue list** (问题清单): a short summary
table per severity group followed by one detail card per issue. A full report
with methodology appendices is opt-in and only produced when the user asks for a
report, audit, or compliance mapping.

## Output language

Write every human-readable part in the language of the user's request (default:
the language they wrote in). Keep machine-readable tokens in canonical English:

- issue IDs (`SR-0001`), lifecycle values, tags, and JSON field names from `references/finding-schema.json`;
- file paths, symbols, commands, and standard identifiers such as `CWE-125` or `SLSA-1.2`.

Localize section headings and field labels with the terminology table below and
use exactly one language profile per output. English evidence inside a localized
list (paths, code, identifiers) does not count as mixing; unlocalized headings
or field labels do.

## Terminology

| Canonical (English) | 中文标签 |
|---|---|
| Security issue list | 安全问题清单 |
| Target / Review mode | 审查对象 / 审查方式 |
| Verdict / Summary counts | 结论 / 统计 |
| ID / Issue / Possible consequence | 编号 / 问题 / 可能导致 |
| Issue details | 问题详情 |
| Issue N (SR-0001) | 问题 N（SR-0001） |
| Coverage and limitations | 覆盖与限制 |
| Risk level / Confidence | 危险等级 / 置信度 |
| Trigger / Root cause / Impact / Nature | 触发条件 / 原因 / 危害 / 性质 |
| Evidence / Fix / Verification | 证据 / 修复 / 验证 |
| Attack chain (optional) | 攻击链（可选） |

Severity labels are localized in the list (`高` / `中` / `低` / `信息`) but keep
the canonical English value in JSON output (`High` / `Medium` / `Low` /
`Informational`).

## Issue list structure

```markdown
# <项目> 安全问题清单

- 审查对象：<repo> @ <commit>（版本 <x.y>）
- 审查方式：<静态只读 / 静态 + 隔离动态>
- 结论：<one-line decision verdict>
- 统计：高危 N / 中危 N / 低危 N / 信息 N（共 N 项）

## 高危（N）

| 编号 | 问题 | 可能导致 |
|---|---|---|
| SR-0001 | <issue in one phrase> | <consequence + precondition> |

## 中危（N）

| 编号 | 问题 | 可能导致 |
|---|---|---|
...

## 低危 / 信息（N）

| 编号 | 问题 | 可能导致 |
|---|---|---|
...

## 问题详情

### 问题 1（SR-0001）：<title>

- 危险等级：高
- 置信度：高
- 触发条件：<who can trigger it, and with which preconditions>
- 原因：<root cause with the code mechanism>
- 危害：<technical + business impact and blast radius>
- 性质：<implementation flaw / design flaw / capability; state whether malicious behavior is evidenced>
- 证据：`path/to/file:line`、`path/to/file:line`
- 修复：<concrete change>
- 验证：<how to confirm the fix without harmful side effects>

## 覆盖与限制

- 覆盖：<phases reviewed; phases that do not exist>
- 已检查未发现：<meaningful negative checks>
- 限制：<what could not be verified and why; mandatory>
```

## Summary table rules

- Every issue appears exactly once, in the severity group that matches its card; the ID column uses the stable `SR-0001` form.
- One line per cell and roughly 40 characters or fewer. The "可能导致" cell states the consequence plus the precondition (remote/local, authentication required).
- No CWE IDs, function names, line numbers, or standard clause numbers in the summary tables; those belong to the detail card.

## Detail card rules

- One card per issue, ordered by severity, in the same order as the summary tables.
- Keep each card to roughly 8-12 lines; merge any extra prose into the nine fields instead of adding new sections.
- `证据` keeps `file:line` references; secrets and personal data are never reproduced.
- Add an optional `- 攻击链：` line only when the path crosses components or findings.

## Coverage and limitations rules

- End every list with a `覆盖与限制` block of 3-5 bullets: coverage, negative
  checks, and limitations. The limitation bullet is mandatory, because a static
  review must not read as proof of exploitability.
- Record lifecycle coverage at the phase level only; per-phase evidence tables
  belong to the optional full report.

## Machine-readable output

When a machine-readable artifact is requested or useful, emit the findings as a
JSON array that conforms to `references/finding-schema.json`;
`references/finding-example.json` shows one complete finding. JSON keeps the
canonical English field names and enum values regardless of the output language.

Run `python scripts/validate_report.py <file.md>` before delivering a file; it
enforces the structure, the single language profile, the summary/detail
consistency, and the enum values described here.

## Optional full report

Produce the extended structure only when the user asks for a report, audit, or
compliance evidence: document control, authorization and scope, executive
summary, system model, lifecycle coverage table, negative evidence, remediation
roadmap, framework crosswalk with versions, and limitations. The issue list
above stays the body of that report; the extra sections become appendices.
