# Security Review Report

Report headings and field labels are localized per `references/output.md`; this
template shows both profiles side by side. Use exactly one profile per report.

## 结论摘要 (TL;DR) / Decision summary

- 结论 / Verdict:
- 最高严重度 / Highest severity:
- 关键风险 / Top risks:
- 可修复性 / Fixability:
- 主要限制 / Key limitation:

## 1. 执行摘要 / Executive summary

- 范围 / Scope:
- 项目类型 / Project type:
- 审查模式 / Review mode: static / safe dynamic / mixed
- 生命周期覆盖 / Lifecycle coverage:
- 主要发现 / Material findings:
- 主要攻击链 / Material attack chains:
- 重要限制 / Important limitations:

## 2. 系统模型 / System model

### 组件 / Components

### 入口点 / Entry points

### 数据与资产 / Data and assets

### 身份与权限 / Identities and privileges

### 外部依赖与服务 / External dependencies and services

### 信任边界 / Trust boundaries

## 3. 生命周期覆盖 / Lifecycle coverage

| 阶段 / Phase | 是否审查 / Reviewed | 证据 / Evidence | 关键结论 / Key findings |
|---|---|---|---|
| 获取 / Acquisition | | | |
| 依赖解析 / Dependency resolution | | | |
| 安装 / Install | | | |
| 构建 / Build | | | |
| 测试 / Test | | | |
| CI/CD | | | |
| 运行 / Runtime | | | |
| 更新 / Update | | | |
| 回滚 / Rollback | | | |
| 卸载 / Uninstall | | | |
| 清理 / Cleanup | | | |
| Agent/隔离模式 / Agent-mediated and isolated mode | | | |

## 4. 发现 / Findings

Use one section per finding following `references/output.md`. A minimal complete
report is in `references/report-example.md`, and `references/finding-example.json`
shows one finding in the machine-readable form defined by
`references/finding-schema.json`. The Markdown report is the primary deliverable;
produce findings JSON in addition only when requested or useful to the consumer.

## 5. 攻击链 / Attack chains

For each chain:

`entry → capability → boundary crossing → asset/action → impact`

Explain which findings contribute to each chain.

## 6. 重要负向证据 / Important negative evidence

List meaningful checks performed with no issue found.

## 7. 修复计划 / Remediation plan

Group by:

1. immediate containment
2. code/config fix
3. dependency/toolchain fix
4. agent policy/control fix
5. verification/regression testing

## 8. 框架对照 / Framework crosswalk

Map material findings to applicable framework identifiers and versions using the
table and versioning rule in `references/framework-crosswalk.md`. Do not invent
requirement mappings.

## 9. 局限与假设 / Limitations and assumptions

Explicitly identify unavailable source, runtime, registry, deployment, operating-system, cloud, or legal context.
