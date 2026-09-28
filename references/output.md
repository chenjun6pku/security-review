# Output Contract

## Decision summary (TL;DR)

Every report opens, before the numbered sections, with a localized decision
summary of 3-6 single-line bullets and no numeric score:

- **结论 / Verdict**: is the project safe to adopt, install, or deploy, and under which conditions;
- **最高严重度 / Highest severity**: highest severity plus finding counts per severity;
- **关键风险 / Top risks**: the one to three material findings, with their IDs;
- **可修复性 / Fixability**: what is fixable in code/config versus what needs design, protocol, or process change;
- **主要限制 / Key limitation**: the single most important blind spot.

A decision verdict is expected; an overall security score is not.

## Output language

Write every human-readable part of the report in the language of the user's
request (default: the language they wrote in). Keep machine-readable tokens in
canonical English:

- domain IDs (`SR-XX`), lifecycle values, tags, and `severity` / `confidence` / `behavior` values;
- JSON field names defined by `references/finding-schema.json`;
- file paths, symbols, commands, and framework identifiers such as `CWE-125` or `SLSA-1.2`.

Localize section headings and field labels with the terminology table below and
use exactly one language profile per report. English evidence inside a localized
report (paths, code, quoted output) does not count as mixing; unlocalized
headings or field labels do.

## Terminology

| Canonical (English) | 中文标签 |
|---|---|
| Decision summary (TL;DR) | 结论摘要（TL;DR） |
| Executive summary | 执行摘要 |
| System model | 系统模型 |
| Lifecycle coverage | 生命周期覆盖 |
| Findings | 发现 |
| Attack chains | 攻击链 |
| Important negative evidence | 重要负向证据 |
| Remediation plan | 修复计划 |
| Framework crosswalk | 框架对照 |
| Limitations and assumptions | 局限与假设 |
| Severity / Confidence / Behavior | 严重度 / 置信度 / 行为分类 |
| Primary domain / Lifecycle / Tags / Affected | 主域 / 生命周期 / 标签 / 受影响位置 |
| Risk / Evidence | 风险 / 证据 |
| Trigger and reachability / Impact | 触发与可达性 / 影响 |
| Attack chain / Why this is or is not malicious | 攻击链 / 恶意性判断 |
| Remediation / Validation | 修复建议 / 验证方法 |

## Finding format

Chinese profile (use the canonical English labels unchanged for an English
report). Field values keep their canonical enum tokens; a short parenthetical
qualifier may follow the token.

```markdown
### [SR-0001] 标题

- 严重度：High
- 置信度：High
- 行为分类：reachable_security_behavior
- 主域：SR-SC
- 生命周期：install, runtime
- 标签：execution, credential-access, exfiltration
- 受影响位置：path/to/file:line

### 风险
<One concise technical statement describing what can happen and to whom/what.>

### 证据
- `path/to/file:line`: <relevant mechanism>
- <configuration/dependency/runtime evidence>

### 触发与可达性
<How the path is reached; required user/attacker action; privilege and preconditions.>

### 影响
<Confidentiality / Integrity / Availability / identity / host / cloud impact and blast radius.>

### 攻击链
`entry → capability → boundary → asset/action → impact`

### 恶意性判断
<Describe observed or inferred behavior without guessing intent.>

### 修复建议
<Concrete code/config/process change.>

### 验证方法
<How to verify the fix without exposing secrets or causing harmful side effects.>
```

Finding IDs are sequential per report in `SR-0001` form. `生命周期` lists every
applicable phase with the primary phase first, and the remaining fields mirror
`references/finding-schema.json`.

The Markdown report is the primary deliverable. When a machine-readable artifact
is requested or useful, also emit the findings as a JSON array that conforms to
`references/finding-schema.json`; `references/finding-example.json` shows one
complete finding. JSON keeps the canonical English field names regardless of the
report language.

Run `python scripts/validate_report.py <report.md>` before delivering a report
written to a file; it enforces the structure, the single language profile, and
the enum values described here.

## Severity ordering

Within the report, order by severity then confidence then blast radius, but do not create a score or ranking of options.

## “Not found” section

Include only meaningful negative checks, for example:

- no automatic persistence discovered in common OS mechanisms;
- no outbound telemetry destination found after inspecting network clients;
- release integrity verification is present;
- container has no host Docker socket mount.

## Limitations

Always list unavailable evidence and scope gaps. Examples:

- external package registry history not available;
- runtime execution not authorized;
- Windows-specific installer not reviewed on Linux;
- cloud deployment configuration absent from repository.
