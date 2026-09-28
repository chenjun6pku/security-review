# MiniEAP 安全性评估报告

| 项目 | 内容 |
| --- | --- |
| 报告编号 | MINIEAP-SR-2026-09-28 |
| 审查对象 | `C:\Users\admin\Desktop\project\minieap`（Git `983fd4a5851d4a344fab92666c5cdb83f26b2294`，2023-09-21，版本 `0.93`，工作区干净） |
| 代码来源 | 远端 `git@github.com:chenjun6pku/minieap.git`（上游 `updateing/minieap` 的 fork） |
| 审查方式 | 纯静态审查（未编译、未运行、未联网；无动态验证） |
| 审查方法 | 生命周期 - 攻击面 - 风险图（security-review v1.1.2）+ 规则筛选（`select_rules.py`）+ 静态扫描（`static_security_scan.py`）+ 人工数据流追踪 |
| 报告日期 | 2026-09-28 |
| 结果概览 | 13 项发现：High 2 / Medium 4 / Low 6 / Informational 1；核心风险为客户机同网段攻击者窃取口令、远程堆越界读取、远程 DoS |

---

## 结论摘要

- **结论**：不建议在未加固的共享二层网络中继续以 root + 明文口令方式部署；需先修复解析器边界与凭据处理缺陷，再评估放行。
- **最高严重度**：High（2 项）；共 13 项发现：2 High / 4 Medium / 6 Low / 1 Informational。
- **关键风险**：① 同网段攻击者可冒充认证服务器并还原口令明文（SR-0001）；② 伪造属性长度可远程越界读取堆内存并致崩溃（SR-0002）；③ 约 4 个伪造报文即可远程断网且不会自动恢复（SR-0003）。
- **可修复性**：解析边界、状态机、PID 文件、指针判空与构建加固均可在代码/部署层修复；SR-0001 属协议字段固有缺陷，需要协议层或流程规避；SR-0005、SR-0011 需调整打包与合规流程。
- **主要限制**：纯静态审查（未编译、未运行、未联网），未比对上游修复状态，许可证结论依赖仓库外信息。

## 目录

- [结论摘要](#结论摘要)
1. [执行摘要](#1-执行摘要)
2. [系统模型](#2-系统模型)
3. [生命周期覆盖](#3-生命周期覆盖)
4. [发现](#4-发现)
5. [攻击链](#5-攻击链)
6. [重要的负向证据](#6-重要的负向证据已检查未发现问题)
7. [修复计划](#7-修复计划)
8. [框架对照](#8-框架对照)
9. [局限与假设](#9-局限与假设)
10. [附录 A：发现索引](#附录-a发现索引)
11. [附录 B：证据文件清单](#附录-b证据文件清单)

---

## 1. 执行摘要

- **项目类型**：Linux/macOS 平台的 C 语言 802.1X（EAP-MD5）客户端，以 root（原始套接字 / BPF 设备）运行；带锐捷 RJv3 私有协议插件；无包管理器、无 CI、无测试。
- **生命周期覆盖**：获取、依赖解析、安装、构建、运行、卸载已审查；测试、CI/CD、更新、回滚在本仓库中不存在（负向证据）。
- **部署身份**：以 root 运行（需要 `AF_PACKET` 原始套接字、`/dev/bpf*`，以及读取根块设备获取磁盘序列号）；systemd 单元以 root 启动。
- **主要发现**：
  1. **同网段攻击者可冒充认证服务器直接还原口令明文**（RJv3 `0x2f` 字段 = `MD5(username‖challenge) XOR password[0..15]`）。
  2. **伪造 EAPOL 帧可触发远程堆越界读取**（属性长度字段未与剩余缓冲区比对），可致崩溃并造成内存内容泄露。
  3. **约 4 个伪造报文即可远程终止客户端**，且发行版服务单元未配置自动重启。
  4. **超长用户名/口令导致栈溢出**，发生在 root 进程内。
  5. **口令以明文存在于命令行、配置文件与日志目录**，本地低权限用户可读取。
  6. **配置文件驱动的 root 命令执行**（`dhcp-script` → `system()`），未校验配置完整性。
- **攻击链**：凭据窃取、远程内存读取/崩溃、断网 DoS、本地提权、root 内存破坏（见第 5 节）。
- **重要限制**：无动态验证（无 ASan/UBSan 实测）、无上游 diff、MentoHUST 许可证原文无法离线核实、未在真实网卡/内核上验证抓包行为。

---

## 2. 系统模型

### 2.1 组件

| 组件 | 位置 | 作用 | 特权 |
| --- | --- | --- | --- |
| 主程序/状态机 | `minieap.c`、`eap_state_machine.c` | EAP/EAPOL 状态机、报文收发、重试与退出策略 | root |
| 配置中心 | `config.c`、`util/conf_parser.c` | 命令行/配置文件解析、口令保存与回写 | root |
| RJv3 插件 | `packet_plugin/rjv3/*` | 私有字段生成、服务端字段解析、心跳、DHCP 钩子 | root |
| 网卡实现 | `if_impl/sockraw`、`if_impl/libpcap`、`if_impl/bpf` | 原始套接字或抓包库收发 0x888e 帧 | root |
| 工具模块 | `util/*` | 日志、闹钟、PID 文件、网络信息、GBK 转换、MD5 | root |
| 内置哈希实现 | `packet_plugin/rjv3/rjv3_hashes/*` | MD5/SHA1/RIPEMD128/Tiger/Whirlpool/CRC16 | root |

### 2.2 入口点

1. **网络**：收到的 `EtherType = 0x888e` 以太网帧（不可信；未校验源 MAC）。
2. **本地**：命令行参数与配置文件（可为非特权用户提供）。
3. **本机环境**：`/etc/resolv.conf`、`/etc/mtab`、根块设备（`HDIO_GET_IDENTITY`）、`getifaddrs()`、`/proc/net` 相关只读信息。
4. **构建系统**：`make`（会执行源码树内的 `minieap.mk`）。

### 2.3 数据与资产

- EAP 用户名与口令（`EAP_CONFIG`，堆上的明文 `strndup` 字符串）。
- 认证会话状态、EAPOL 帧缓冲区、心跳 echo key。
- root 权限、日志文件、配置文件、PID 文件。
- 宿主机指纹：网卡 MAC、链路本地/全局 IPv6、DNS 服务器、根磁盘序列号、伪造的版本串。

### 2.4 身份与特权

- 进程身份：root（可直接使用原始套接字与块设备；`system()` 以 root 执行）。
- 认证身份：EAP 用户名/口令；RJv3 私有字段中的“客户端指纹”。
- 本地其他用户：可读 `0644` 的配置文件与日志（取决于 umask）。

### 2.5 外部依赖/服务

- 认证服务器：二层可达、无 TLS、无服务器身份验证（EAP-MD5 本身不提供服务器认证）。
- 可选构建依赖：`libpcap`、`libiconv`（动态链接，无版本锁定）。
- 随源码内置的第三方哈希实现（rhash 派生 + GPLv3 组件 + 无头文件）。

### 2.6 信任边界

1. `不可信二层报文 → 协议解析器`（SR-0001、SR-0002、SR-0003）
2. `认证服务器 → 客户端凭据`（SR-0001）
3. `配置/命令行 → root 命令执行`（SR-0006）
4. `本地普通用户 → 口令/日志/PID 路径`（SR-0005、SR-0007）
5. `源码树 → 构建系统`（SR-0011、SR-0012）

---

## 3. 生命周期覆盖

| 阶段 | 是否审查 | 证据 | 关键结论 |
| --- | --- | --- | --- |
| 获取 | 部分 | `.git/config`、`README.md` | 本地 clone 已审查；上游仓库/发布包、校验和、签名无法离线核实 |
| 依赖解析 | 是 | 无锁文件；`md5.c`、`rjv3_hashes/*` 为内置代码 | 无包管理器；第三方代码内嵌，部分文件无许可证头（SR-0011） |
| 安装 | 是 | `Makefile:82-90` | `install -m 644 minieap.conf`（含明文口令）；`systemctl enable` 安装期修改系统 |
| 构建 | 是 | `Makefile`、`append.mk`、`minieap.mk` | 无加固编译参数；自动 include 源码树内任意 `minieap.mk`（SR-0012） |
| 测试 | 否（不存在） | 仓库无 test 目录 | 无回归/模糊测试 |
| CI/CD | 否（不存在） | 无 `.github/workflows` | 无自动化审查门禁 |
| 运行 | 是 | 状态机、插件、工具模块 | SR-0001 ~ SR-0009 全部位于运行期 |
| 更新 / 回滚 | 否（不存在） | 无自更新代码 | 负向证据：无自动更新、无降级通道 |
| 卸载 | 是 | `Makefile:93-99` | 不删除含口令的配置与日志（SR-0009） |
| 清理 | 是 | `pid_lock_destroy()` | 退出时删除 PID 文件；口令内存不擦除 |
| Agent/隔离模式 | 不适用 | 无 AI/Agent/MCP/插件加载组件 | 无 `dlopen`、无 MCP、无模型调用 |

---

## 4. 发现

### [SR-0001] 同网段攻击者可冒充认证服务器并还原出口令明文

- 严重度：High
- 置信度：High
- 行为分类：reachable_security_behavior
- 主域：SR-AS
- 生命周期：runtime
- 标签：credential-access, exfiltration, network-facing, confidentiality, network
- 受影响位置：`packet_plugin/rjv3/rjv3_hashes/checkV4.c:1160-1179`、`packet_plugin/rjv3/packet_plugin_rjv3_priv.c:50-60`、`packet_plugin/rjv3/packet_plugin_rjv3_priv.h:16-17`

### 风险

客户端发送的 RJv3 `0x2f` 字段等于 `MD5(username ‖ challenge) XOR password[0..15]`。攻击者自己挑选 `challenge`、已知 `username`，把收到的 16 字节与本地重算的 MD5 异或，即得**口令前 16 个字符的明文**；同时标准 EAP-MD5 响应 `MD5(id‖password‖challenge)` 允许对其余字符做离线字典/暴力破解。

### 证据

- `checkV4.c:1171-1178`：`buf = MD5(username‖md5)`；`memset(tmp,0,16)`；`strcpy(tmp,password)`；`buf[i] ^= tmp[i]`。
- `packet_plugin_rjv3_priv.c:290` → `rjv3_set_pwd_hash()` → 结果以 16 字节属性写入待发报文（`RJV3_TYPE_PWD_HASH 0x2f`，见 `packet_plugin_rjv3_priv.h:16-17`）。
- `eap_state_machine.c:241-260`：状态机接受**任意源 MAC** 的 `EAP-Request`，并把回包发往该 MAC（`PRIV->server_mac` 取自报文源地址）。

### 触发与可达性

任意二层可达主机发送 `EAP-Request/Identity`，随后发送 `EAP-Request/MD5-Challenge`，即可收到完整凭据；无需认证、无需用户交互、无需处于特定状态（仅需启用 `rjv3` 插件，即示例配置默认值）。

### 影响

校园网/企业账号被窃取（会话可被他人使用、账号被共享或滥用）；口令若被复用，影响面扩展到其它系统。属于协议实现固有缺陷（源自被逆向的锐捷 v3 方案），无法在保持兼容的前提下彻底修复。

### 攻击链

`二层注入 EAP-Request → 客户端回送 Identity + MD5 响应 + 0x2f 口令异或值 → 攻击者本地计算 MD5(username‖challenge) 并异或 → 口令明文`

### 恶意性判断

代码路径完全公开且属于协议字段构造逻辑，无隐藏外发通道；无恶意意图证据。问题在于该字段的密码学构造本身泄露口令。

### 修复建议

无法在不破坏兼容的情况下改变线上字段；应：① 文档中明确“口令会以可逆形式暴露给认证服务器”；② 使用一次性/专用账号，禁止复用重要口令；③ 仅在受控二层域使用；④ 长期方案是改用 EAP-TLS/PEAP 或厂商修复后的协议。

### 验证方法

在隔离实验网中用合成账号（如 `testuser / known-password-12345`）抓包，验证由 `0x2f` 字段可还原口令；不涉及真实凭据。

---

### [SR-0002] RJv3 属性长度未校验导致远程堆越界读取（可致崩溃与信息泄露）

- 严重度：High
- 置信度：High
- 行为分类：reachable_security_behavior
- 主域：SR-AS
- 生命周期：runtime
- 标签：memory, data-access, exfiltration, availability, network-facing
- 受影响位置：`packet_plugin/rjv3/packet_plugin_rjv3_prop.c:187-262`、`packet_plugin/rjv3/packet_plugin_rjv3_priv.c:441-495`、`util/misc.c:169-184`

### 风险

解析服务器报文时，属性内容长度直接取自报文中的 `header2.len`（uint8_t），**未与剩余缓冲区长度比较**，`memdup()` 会按该长度读取帧缓冲区之后的内存（堆越界读，最多约 247 字节）。读取到的数据随后进入日志（最多约 253 字节）和心跳包（每次 4 字节回传攻击者），也可在跨页时触发 SIGSEGV。

### 证据

- `packet_plugin_rjv3_prop.c:205`：`_content_len = header2.len - 6 + 4`，仅校验 `len >= 2`（`:179`），没有 `_read_len + _content_len <= buflen` 检查；`:212-215` 立刻按该长度 `memdup`。
- `packet_plugin_rjv3_prop.c:209`：另一分支用“下一个 magic”定位时同样只按可用缓冲截断；若 magic 出现在偏移 0/1 还会得到负长度（`-1/-2`）。
- `packet_plugin_rjv3_priv.c:448-453`：调用方以 `frame->actual_len - 22` 为长度、`frame->content + 22` 为起点调用解析器，**且忽略返回值**，解析失败仍继续使用部分结果。
- `util/packet_util.c:17-24`：接收帧被复制为 `malloc(actual_len)` 的精确堆块，故越界读发生在堆块边界之外。
- `packet_plugin_rjv3_priv.c:456-462`：读出的内容经 `pr_info_gbk()` 写入日志；`packet_plugin_rjv3_prop.c:32-46` 复制到新的堆块。
- `packet_plugin_rjv3_priv.c:478-491`：`type=0x1` 属性未校验 `content` 至少 10 字节即读 `content[6..9]`，该 4 字节被 `bit_reverse(~x)` 后写入 Keep-Alive 报文，目的 MAC 由攻击者报文的源 MAC 决定。

### 触发与可达性

任意二层可达主机发送一帧 `EtherType=0x888e`、EAP code = Success(3) 或 Failure(4) 的报文（最小以太网帧 60 字节即可），在偏移 22 放置 magic `00 00 13 11`、`type=0x01`、`len=0xFF`。客户端在**任何认证状态**下都会解析，无需认证成功。

### 影响

- 机密性：最多约 253 字节堆内存写入日志（日志文件权限取决于 umask，通常 0644，本地任意用户可读）；`type=0x1` 路径每次心跳向攻击者回传 4 字节相邻堆数据（可通过调整帧长微调偏移）。
- 可用性：读取跨出映射页时进程崩溃；服务单元无自动重启（SR-0003），导致持续离线。
- 由于口令和用户名以明文常驻堆内存（SR-0005），泄露内容存在包含凭据的风险。

### 攻击链

`二层伪造 EAP-Success/Failure → 属性长度 0xFF → memdup 越界读堆 → 日志写入 / Keep-Alive 回传 / SIGSEGV 崩溃`

### 恶意性判断

典型的解析器边界缺陷（CWE-125），代码中无任何隐藏数据外发逻辑；日志与心跳通道为既有功能，被越界数据顺带利用。

### 修复建议

① 在 `parse_rjv3_buf_to_prop_list()` 中把 `_content_len` 限制为 `buflen - _read_len`，并对负值返回失败；② 对 `PROP_TO_CONTENT_SIZE()` 做下界检查；③ 在调用处检查返回值；④ 对已知类型要求最小内容长度（`0x01` → ≥10）；⑤ 在 CI 中对解析器加 ASan/UBSan + libFuzzer 目标。

### 验证方法

用合成报文（`type=0x01, len=0xFF`，帧长 60）在 ASan 构建下复现 heap-buffer-overflow；修复后断言无报告且心跳不再携带越界数据。

---

### [SR-0003] 少量伪造报文即可远程终止客户端且不会自动恢复

- 严重度：Medium
- 置信度：High
- 行为分类：reachable_security_behavior
- 主域：SR-AS
- 生命周期：runtime
- 标签：availability, network-facing, network
- 受影响位置：`eap_state_machine.c:200-220`、`eap_state_machine.c:343-372`、`minieap.service.in`

### 风险

状态机把“重试计数达到阈值”“同状态停留次数达到 `max_retries`（默认 3）”以及“掉线且未开启自动重连”直接处理为 `exit(EXIT_FAILURE)`。攻击者发送 4 个连续的 `EAP-Request/Identity` 或 `EAP-Failure` 报文即可让进程退出；随发行版本的系统服务未设置 `Restart=`，进程不会自动拉起。

### 证据

- `eap_state_machine.c:215-217`：`++fail_count == max_failures`（默认 3）→ `exit(EXIT_FAILURE)`。
- `eap_state_machine.c:346-352`：同一状态重复计数到 `max_retries`（默认 3）→ `exit(EXIT_FAILURE)`。
- `eap_state_machine.c:205-211`：`--no-auto-reauth` 下，处于 Success 后收到 Failure 直接退出。
- `minieap.service.in:6-9`：无 `Restart=`、无 watchdog（systemd 默认 `Restart=no`）。

### 触发与可达性

任意二层可达主机，无需认证、无需知道客户端状态；发送 4 帧带 `EAPOL-EAP` 头的报文即可复现（`eap_state_machine.c:241-260` 不校验源 MAC）。

### 影响

可用性：用户被强制断网，且直到人工 `systemctl restart` 之前无法恢复；可与 SR-0002 的崩溃路径叠加。

### 攻击链

`二层注入重复 EAP 报文 → 重试/同状态计数达阈值 → exit(EXIT_FAILURE) → 无 Restart 策略 → 长期断网`

### 恶意性判断

退出逻辑是设计上的“重试上限”语义（对服务器无响应也生效），未发现隐藏行为；但缺少源校验与守护重启使其实质上可被滥用为 DoS。

### 修复建议

① 对收到的帧校验目的 MAC/源 MAC 与当前会话一致；② 关键错误不应 `exit()`，改为回退状态或发布告警；③ 服务单元增加 `Restart=always`、`RestartSec`、`WatchdogSec`；④ 把“认证失败次数”与“收到伪造报文次数”分开统计。

### 验证方法

在实验网抓包构造上述报文序列，确认修复后进程存活且状态复位（不执行真实攻击）。

---

### [SR-0004] 长用户名/口令导致栈缓冲区溢出（root 进程内存破坏）

- 严重度：Medium
- 置信度：High
- 行为分类：reachable_security_behavior
- 主域：SR-AS
- 生命周期：runtime
- 标签：memory, privilege-escalation, execution, integrity
- 受影响位置：`packet_plugin/rjv3/rjv3_hashes/checkV4.c:1160-1179`、`packet_builder.c:29-40`、`include/config.h:12-13`

### 风险

`USERNAME_MAX_LEN`/`PASSWORD_MAX_LEN` 允许 64 字符，但内部使用 40 字节和 80 字节栈数组：`computePwd()` 中 `strcpy(tmp, username)` 最多越界 24 字节（随后 `memcpy(tmp+len, md5, 16)` 再写 16 字节），`hash_md5_pwd()` 在 64 字符口令时越界 1 字节（写入值来自服务器可控的 challenge 末字节）。无栈保护的构建可造成控制流劫持，有 canary 的构建会直接 abort。

### 证据

- `checkV4.c:1164-1174`：`unsigned char tmp[40]` + `strcpy(tmp, username)`（用户名最长 64）与 `strcpy(tmp, password)`。
- `packet_builder.c:32-38`：`uint8_t md5Src[80]`，`1 + 65 + 16 = 82 > 80`。
- `config.c:132-133`：用户名/口令通过 `strndup(argument, 64)` 进入配置。
- `Makefile:4`：编译参数仅 `-Wall -Wpedantic -D_GNU_SOURCE`，未显式启用栈保护/加固。

### 触发与可达性

本地使用 >39 字符用户名或 64 字符口令运行（或写入配置文件后由 root 服务读取）。远端只能“触发”该代码路径（发送 MD5-Challenge），不能控制长度。

### 影响

root 进程栈内存破坏 → 崩溃（有 canary）或潜在任意代码执行（无 canary / 特定布局）；也影响认证可靠性。

### 攻击链

`配置/命令行提供超长凭据 → 认证握手 → computePwd/hash_md5_pwd 栈溢出 → root 进程内存破坏 → 崩溃或代码执行`

### 恶意性判断

缓冲区尺寸与凭据长度上限不匹配，属典型实现缺陷（CWE-121）；未发现隐藏行为或意图证据，静态审查也无法确认实际可控性，故不升级为可疑或恶意。

### 修复建议

校验凭据长度上限（≤39 / ≤63）并失败退出；把 `tmp`/`md5Src` 改为按需动态分配或使用 `snprintf`/`memcpy` + 显式长度检查；启用 `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2`。

### 验证方法

用 48 字符用户名、64 字符口令在 ASan 构建中运行，确认报错；修复后用同样输入验证无越界并给出明确错误提示。

---

### [SR-0005] 口令以明文出现在命令行、配置文件和日志目录中

- 严重度：Medium
- 置信度：High
- 行为分类：reachable_security_behavior
- 主域：SR-ID
- 生命周期：runtime, install, uninstall
- 标签：credential, data-access, local-user-assisted, privacy
- 受影响位置：`config.c:132-133`、`config.c:253-272`、`util/conf_parser.c:162-166`、`Makefile:85`

### 风险

① README/手册推荐 `-p <口令>`，口令进入 `/proc/<pid>/cmdline`、`ps` 输出、shell history，以及 `sudo` 写入的 auth 日志；② `--save`/`save_config_file()` 用 `fopen(path,"w")` 写明文口令，权限由 umask 决定（通常 0644），且 `make install` 安装示例配置为 `644`；③ 进程退出时口令堆内存未擦除。任何本地用户（或用 `ps` 的自动化）都能获得凭据。

### 证据

- `config.c:132-133`、`config.c:257`：命令行/配置的 password 字段；`README.md:73` 的示例直接带 `-p 15000000000`。
- `util/conf_parser.c:162`：`fopen(g_conf_file, "w")`（无 `0600`、无 `fchmod`）。
- `Makefile:85`：`install -m 644 minieap.conf`。
- `config.c:306`：`chk_free(&password)`（普通 `free`，不擦除）。
- `Makefile:93-99`：`uninstall` 不删除 `/etc/minieap.conf` 与日志文件。

### 触发与可达性

本地多用户主机上的任意用户执行 `ps aux`、读取 `/etc/minieap.conf`、读取 `/var/log/minieap.log`（依赖 umask）或 shell history 即可获得口令；`--save` 由操作者一次触发生效。

### 影响

凭据泄露给本地低权限用户 → 账号盗用 / 网络接入滥用；与 SR-0001 叠加后凭据可被网络侧窃取。

### 攻击链

`root 用户以 -p 启动或执行 --save → 口令落到 argv/0644 配置文件/日志 → 本地普通用户读取 → 账号盗用`

### 恶意性判断

口令处理方式与 README 推荐用法一致，属不安全的默认值与文件权限设计；未发现外传、隐藏收集或规避审计的行为。

### 修复建议

支持口令文件/交互输入（`--password-file`、`getpass`）并弃用命令行明文；保存配置与日志时使用 `open(..., O_CREAT, 0600)` + `fchmod`；对凭据内存 `explicit_bzero`；`make install` 时以 `600` 安装配置并提示 `chmod 600`；在文档中去掉带 `-p` 的示例。

### 验证方法

在测试机上检查 `ls -l /etc/minieap.conf /var/log/minieap.log` 与 `ps` 输出是否仍出现口令；验证 `--save` 后文件权限为 600。

---

### [SR-0006] 配置驱动的 root 命令执行（`dhcp-script` → `system()`），且未校验配置完整性

- 严重度：Medium
- 置信度：High
- 行为分类：security_relevant_capability
- 主域：SR-HP
- 生命周期：runtime, install
- 标签：execution, privilege-escalation, persistence, local
- 受影响位置：`packet_plugin/rjv3/packet_plugin_rjv3.c:236-254`、`util/conf_parser.c:76-95`

### 风险

认证成功后，插件以 root 身份执行 `system(PRIV->dhcp_script)`（`/bin/sh -c`，默认值为空串）。脚本串可来自配置文件或 `--dhcp-script`，程序在使用前不校验配置文件的属主、权限与路径可信性，也不限制脚本内容。

### 证据

- `packet_plugin_rjv3.c:253`（默认 `dhcp_type=DHCP_AFTER_AUTH` 的必经路径）与 `:237`（二次认证路径）。
- `util/conf_parser.c:80`：以 root 打开任意 `--conf-file` 路径；`config.c:253-272` 会回写该文件。
- `Makefile:85`：安装时配置为 `644`；若部署方改用组/其他可写目录，即形成提权链。

### 触发与可达性

需要“非 root 用户对该配置文件路径具备写权限”（或服务被指向用户可写的 `--conf-file`）。此时一次认证成功即触发 root 命令执行；若配置路径在 `/etc` 且为 root 所有 600/644，则无法利用。

### 影响

本地权限提升到 root（宿主完全失控）、可持久化；也可被用来在 root 环境下执行任意命令。

### 攻击链

`本地用户写配置（dhcp-script=…）→ root 服务读取 → 认证成功 → system() → root 命令执行`

### 恶意性判断

`system()` 是插件文档化的 DHCP 钩子能力，默认值为空串；风险来自缺少配置完整性与权限校验，而非恶意意图，因此归类为 security_relevant_capability。

### 修复建议

① 启动时校验配置文件属主为 root 且不可被组/其他用户写（`stat` + `S_IWGRP|S_IWOTH` 检查），不合格则拒绝启动；② 用 `posix_spawn`/`execv` 传入参数数组，避免 shell 解释；③ 要求脚本路径为绝对路径、属主 root、不可写；④ 单元文件中对配置与日志使用 `ProtectSystem=strict` 等约束。

### 验证方法

在测试环境把配置放到 0777 目录并写入 `dhcp-script=/bin/echo pwned`，确认程序拒绝启动；权限修正后确认正常认证。

---

### [SR-0007] PID 文件：跟随符号链接、未终止读取、以 root 身份按文件内容杀进程

- 严重度：Low
- 置信度：High
- 行为分类：security_relevant_capability
- 主域：SR-HP
- 生命周期：runtime
- 标签：local, integrity, availability, privilege-escalation
- 受影响位置：`util/pid_lock.c:24-90`

### 风险

`open(pidfile, O_RDWR|O_CREAT, 0644)` 未使用 `O_NOFOLLOW|O_EXCL|O_CLOEXEC`；`read()` 结果未做 NUL 终止（空文件时读取未初始化栈并 `atoi`）；解析出的 PID 直接用于 `kill(pid, SIGTERM)`（root 身份），退出时 `unlink(pidfile)`。

### 证据

- `pid_lock.c:29`（open 标志）、`:42`（`read` 与未初始化缓冲）、`:53/:57`（`kill(pid, SIGTERM)`）、`:119`（`unlink`）。

### 触发与可达性

需要 PID 文件位于攻击者可写目录（例如 `--pid-file /tmp/minieap.pid` 或自定义 init 脚本）；默认 `/var/run/minieap.pid` 由 root 拥有，不可利用。此时可：① 写伪造 PID 让 root 终止任意进程（含 PID 1 造成重启）；② 通过符号链接让 root 打开并写入任意文件偏移 0 处（内容为十进制 PID）。

### 影响

本机拒绝服务、文件内容破坏；因默认路径安全，实际利用需要非默认部署。

### 攻击链

`攻击者控制 pidfile 路径/目录 → 符号链接或伪造内容 → root 打开/写入/kill → 任意进程被终止或文件被破坏`

### 恶意性判断

属常规 PID 文件实现的稳健性缺陷（缺少 `O_NOFOLLOW`、长度与 PID 校验）；默认路径下不可利用，未见攻击者导向的设计痕迹。

### 修复建议

使用 `open(path, O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600)` + `flock` + `ftruncate`；校验 `read()` 返回值、显式置 `'\0'`、用 `strtol` 严格解析并校验 PID > 1；对 pidfile 目录做属主/权限校验。

### 验证方法

在临时目录构造符号链接与含 `1` 的 pid 文件，确认修复版本不跟随链接、不执行 `kill`（不实际对生产主机验证）。

---

### [SR-0008] getifaddrs/resolv.conf 指针未判空导致本地崩溃

- 严重度：Low
- 置信度：High
- 行为分类：reachable_security_behavior
- 主域：SR-AS
- 生命周期：runtime
- 标签：availability, memory
- 受影响位置：`util/net_util.c:45-90`、`packet_plugin/rjv3/packet_plugin_rjv3_priv.c:64-90`、`packet_plugin/rjv3/packet_plugin_rjv3_priv.c:212-226`

### 风险

多处直接解引用可能为 NULL 的指针：`if_curr->ifa_addr->sa_family`（接口无地址时 `ifa_addr` 可为 NULL）；`rjv3_set_ipv6_addr()` 对可能为 NULL 的地址链表执行 `do…while`（`IP_ELEM->family` 即空指针解引用）；`rjv3_get_dhcp_lease()` 在 `/etc/resolv.conf` 无 nameserver 时使用 `_dns_list->content`。这些路径都在正常启动/认证流程中。

### 证据

- `util/net_util.c:53`、`:57`、`:80`：无 `ifa_addr` 判空（`getifaddrs()` 对无地址接口会返回 NULL）。
- `packet_plugin_rjv3_priv.c:72-88`：`_ip_curr = _ip_list; do { IP_ELEM ... } while (...)`。
- `packet_plugin_rjv3_priv.c:222`：`_dns1_str = _dns_list->content;`。

### 触发与可达性

本地环境触发（接口无 IPv4/IPv6 地址、`--nic` 拼写错误、容器内无 `/etc/resolv.conf` nameserver 条目）；每次发送报文都会经过该路径。

### 影响

客户端启动即崩溃或认证中途崩溃 → 断网；可与 SR-0003 的“无自动重启”叠加。

### 攻击链

`环境缺少接口地址或 nameserver → 未判空解引用 → 启动或认证中崩溃 → 断网（叠加无自动重启）`

### 恶意性判断

空指针路径属缺少防御性检查的可用性缺陷，无安全意图证据；其影响依赖部署环境，故未按可利用漏洞定级。

### 修复建议

统一判空并返回失败/降级（缺 IPv6 时留空、缺 DNS 时提示使用 `--fake-dns1`）；为这些路径补充单元测试。

### 验证方法

在无地址接口与空 resolv.conf 环境（容器）中运行，确认给出明确错误而非崩溃。

---

### [SR-0009] 卸载不清理含口令的配置与日志

- 严重度：Low
- 置信度：High
- 行为分类：benign_or_expected_capability
- 主域：SR-LC
- 生命周期：uninstall, cleanup
- 标签：credential, local, privacy
- 受影响位置：`Makefile:93-99`

### 风险

`make uninstall` 仅删除二进制、man page 与服务文件，保留 `/etc/minieap.conf`（明文口令，SR-0005）与 `/var/log/minieap.log`（可能含被越界读取出的堆内容，SR-0002）；重装或弃用后凭据仍留在磁盘上。

### 证据

- `Makefile:93-99`：uninstall 目标不含配置/日志删除或告警。

### 触发与可达性

运维执行卸载/迁移时必然发生；无需攻击者参与。

### 影响

凭据与潜在敏感堆内容长期残留，增加后续被读取的风险。

### 攻击链

`执行 make uninstall → 配置与日志未被清理 → 明文口令与潜在越界读取内容留存磁盘 → 后续被本地用户或取证读取`

### 恶意性判断

保留配置是常见打包取舍（避免误删用户数据），并非恶意；但结合明文口令与越界日志，该默认值构成安全卫生问题。

### 修复建议

在 uninstall 中提示或（带 `--purge` 语义地）删除配置与日志，或明确文档说明保留路径与建议的手工清理步骤；把口令改为独立文件后一并处理。

### 验证方法

在容器内执行 `make DESTDIR=… uninstall`，检查残留文件清单。

---

### [SR-0010] 构建与运行加固缺失

- 严重度：Low
- 置信度：High
- 行为分类：security_relevant_capability
- 主域：SR-BL
- 生命周期：build, deploy
- 标签：host-compromise, integrity, local
- 受影响位置：`Makefile:4`、`minieap.service.in`

### 风险

① 编译仅 `-Wall -Wpedantic`，未显式启用 `-O2/-fstack-protector-strong/-D_FORTIFY_SOURCE=2/-fPIE/-pie/-Wl,-z,relro,-z,now`（配合自定义链接脚本 `minieap_init_func.lds`，需确认 RELRO/PIE 未被削弱）——对 SR-0004 这类栈溢出影响重大；② 服务单元以 root 运行，无 `Restart=`、无 `AmbientCapabilities=CAP_NET_RAW`、无 `PrivateTmp/ProtectSystem/NoNewPrivileges`；③ `StandardOutput=null` 使 OOB 泄露日志（SR-0002）被丢弃，同时降低可观测性。

### 证据

- `Makefile:4`：CFLAGS 组成；无加固开关。
- `minieap.service.in:6-9`：无 Restart/沙箱/能力配置；`StandardOutput=null`。
- `packet_plugin_rjv3_priv.c:162-172`：需要读取根块设备（`HDIO_GET_IDENTITY`），这是保持 root 的原因之一；可用 `--fake-serial` 规避。

### 触发与可达性

构建/部署阶段；与运行期漏洞叠加放大影响。

### 影响

降低攻击门槛（无 canary/fortify 时栈溢出更易利用）；服务不可自动恢复；权限过大扩大漏洞影响面。

### 攻击链

`默认 CFLAGS 无加固 + 服务单元无沙箱/无 Restart → 栈溢出与越界缺陷更易利用、崩溃后不自动恢复 → 前述运行期风险被放大`

### 恶意性判断

加固缺失属构建与部署默认值问题，未发现主动削弱安全控制的代码；归类为 security_relevant_capability。

### 修复建议

加入加固编译参数并在 CI 中断言（`checksec` / `readelf -lW | grep GNU_RELRO`）；单元文件加入 `Restart=always`、`CapabilityBoundingSet=CAP_NET_RAW`、`AmbientCapabilities=CAP_NET_RAW`、`User=minieap`、`ProtectSystem=strict`、`PrivateTmp=yes`，并配合 `--fake-serial` 去掉块设备访问。

### 验证方法

`readelf -lW minieap` 检查 RELRO/PIE；用 `systemd-analyze security minieap.service` 评估单元加固分数变化。

---

### [SR-0011] 内置第三方代码的出处、许可证与发布完整性

- 严重度：Low
- 置信度：Medium（许可证结论依赖仓库外信息）
- 行为分类：benign_or_expected_capability
- 主域：SR-SC
- 生命周期：acquisition, dependency-resolution, build
- 标签：supply-chain, ip-license, integrity
- 受影响位置：`packet_plugin/rjv3/rjv3_hashes/*`、`LICENSE`、`md5.c`

### 风险

① 内置哈希实现混合了 MIT/BSD 风格（rhash：`rjmd5.c`、`rjsha1.c`、`rjtiger.c`、`rjwhirlpool.c`、`byte_order.c`；`rjcrc16.c`）与 **GPL-3.0-or-later**（`ampheck.h`、`rjripemd128.[ch]`）代码，而 `checkV4.c`、`rjencode.c` 等文件**无任何许可证头**且 README 声明源自 MentoHUST（GPLv2）：若 MentoHUST 为 GPLv2-only，则与仓库根部的 GPLv3 组合存在许可不兼容风险（无法离线核实，需上游确认）；② `checkV4.c` 中 `array[1820]`/`array_1[2035]` 是从锐捷 `8021x.exe` 提取的二进制数据（含 `.rdata` 片段），来源与再分发授权不明；③ `md5.c` 的 RSA 许可要求在所有材料中标注出处，仓库文档/手册未提及；④ 无校验和、签名、可重复构建声明，无 CI。

### 证据

- `ampheck.h:3-16`、`rjripemd128.c:3-16`（GPLv3 头）；`rjmd5.c:3-8`、`byte_order.c:3-8`（MIT 风格）。
- `checkV4.c`：无版权/许可证头；含提取自厂商二进制的常量块。
- `md5.c:3-19`：RSA 许可条款（要求标注出处）。
- 仓库无 `SHA256SUMS`、无 `.github/`、无打包脚本。

### 触发与可达性

构建与再分发时生效（法律/合规风险），非运行期技术漏洞；静态证据充分，许可证兼容性需外部确认。

### 影响

再分发合规风险（ip-license）；缺少完整性校验使消费者无法验证产物与源码一致性（SLSA 1.2 溯源缺口）。

### 攻击链

`混合许可证的 vendored 代码 + 无出处标注 → 再分发合规风险；无校验和/签名 → 产物与源码一致性不可验证`

### 恶意性判断

许可证与出处问题属合规与供应链卫生范畴，无技术恶意证据；兼容性结论依赖仓库外信息，故置信度为 Medium。

### 修复建议

为每个 vendored 文件补齐原始许可证头与出处说明；确认 MentoHUST 许可证并处理 GPLv2/GPLv3 组合；在 README/手册中加入 MD5 归属声明；发布 `SHA256SUMS` 与签名产物，记录构建来源。

### 验证方法

用 `reuse`/`scancode` 之类工具生成 SBOM 与许可证清单并人工复核。

---

### [SR-0012] 构建期插件信任模型（Informational）

- 严重度：Informational
- 置信度：High
- 行为分类：benign_or_expected_capability
- 主域：SR-BL
- 生命周期：build
- 标签：build-time, execution, supply-chain
- 受影响位置：`Makefile:14-19`、`include/module_init.h`、`packet_plugin/packet_plugin.c:16-27`

### 风险

`MK_LIST := $(shell find . -name minieap.mk)` 会 include 源码树内**任意位置**的 `minieap.mk`，构建即执行其内容（`$(shell …)`、编译其 `LOCAL_SRC_FILES`）；插件通过链接器段（`.pktplugininit`/`.ifimplinit`）自动注册，无白名单。解包来源不明 tarball/分支后直接 `make` 即等于以构建者身份执行任意代码。

### 证据

- `Makefile:14-19`：`find` + `include $(MK_LIST)`；`append.mk` 中规则由 `LOCAL_*` 变量驱动。
- `include/module_init.h:5-6`：`__section__` 自动注册；`packet_plugin/packet_plugin.c:16-27` 遍历段内所有构造函数并实例化。

### 触发与可达性

仅构建期（本地）；运行期无 `dlopen`，插件不能动态加载（负向证据）。

### 影响

“构建不受信任源码树 = 代码执行”属 Make 生态固有属性；代码审查层面的启示：新增 `minieap.mk` 或 `packet_plugin/*` 文件都应视为可执行代码变更。

### 攻击链

`不可信源码树 → find 收集任意 minieap.mk → make include 并执行其内容 → 以构建者身份执行任意代码`

### 恶意性判断

这是 Make 生态的固有属性与该项目的构建约定，而非隐藏的恶意设计，因此标为 Informational。

### 修复建议

在 CI 中校验源码哈希/签名后再构建；对 `find` 结果限定目录白名单；为插件注册增加显式清单。

### 验证方法

在隔离目录放入携带 `$(shell touch /tmp/pwn)` 的 `minieap.mk`，确认构建会执行（仅在一次性沙箱内验证）。

---

### [SR-0013] 主机指纹信息被采集并发送给认证服务器

- 严重度：Low
- 置信度：High
- 行为分类：reachable_security_behavior
- 主域：SR-DA
- 生命周期：runtime
- 标签：privacy, data-access, collection, network
- 受影响位置：`packet_plugin/rjv3/packet_plugin_rjv3_priv.c:56-186`、`util/net_util.c:100-125`

### 风险

每次认证都会把本机标识发送到认证方：网卡 MAC（`0x2d`）、链路本地/临时/全局 IPv6（`0x36/0x38/0x4e`）、`/etc/resolv.conf` 中的次要 DNS（`0x76`）、`/etc/mtab` + 根块设备 `HDIO_GET_IDENTITY` 得到的**磁盘序列号**（`0x54`），以及伪造的序列号/DNS/版本（`--fake-*`）。恶意或失陷的认证服务器可据此做设备指纹与跨网络跟踪。

### 证据

- `packet_plugin_rjv3_priv.c:56`（MAC）、`:64-90`（IPv6）、`:108-128`（DNS）、`:130-186`（读 `/etc/mtab`、`open(根设备)`、`HDIO_GET_IDENTITY`、发送 `serial_no`）。
- `util/net_util.c:104`（解析 `/etc/resolv.conf`）。
- 上述字段在 `rjv3_append_common_fields()` 中无条件加入待发报文。

### 触发与可达性

正常认证流程；远端只能被动收集（服务器侧可控），本地可用 `--fake-serial/--fake-dns1/--fake-dns2` 替代真实值。

### 影响

隐私：硬件唯一标识与网络配置被第三方长期记录，可用于跨网络关联用户；磁盘序列号属较高敏感度的主机指纹。

### 攻击链

`正常认证 → 组装 MAC/IPv6/DNS/磁盘序列号字段 → 发送至认证服务器 → 服务器侧长期指纹化与跨网络关联`

### 恶意性判断

字段采集是为兼容私有协议而对齐厂商客户端行为的结果，未见发送给第三方或隐藏通道的证据；问题在于采集范围与披露不足。

### 修复建议

默认使用可配置的随机/占位序列号（需与服务端策略兼容）；在文档中明确列出会上报的字段；提供 `--no-fingerprint` 之类的开关；避免直接读取根块设备。

### 验证方法

抓包核对字段清单，与 `--fake-*` 配置后的输出对比。

---

## 5. 攻击链

| 链 ID | 路径 | 关联发现 |
| --- | --- | --- |
| CHAIN-1 凭据窃取 | `二层广播/伪造认证服务器 → EAP-Request/Identity + MD5-Challenge → 客户端回送 0x2f 字段 → 攻击者计算 MD5(username‖challenge) 并异或 → 口令明文（其余字符离线爆破）` | SR-0001、SR-0005 |
| CHAIN-2 远程内存读取 / 崩溃 | `伪造 EAP-Success/Failure（属性 len=0xFF）→ 解析器越界读堆 → ①日志写入最多约 253 字节 ②Keep-Alive 回传 4 字节到攻击者 MAC ③跨页 SIGSEGV` | SR-0002、SR-0005、SR-0003、SR-0010 |
| CHAIN-3 断网 DoS | `重复 EAP-Request/EAP-Failure（约 4 帧）→ fail_count/state_last_count 达阈值 → exit(EXIT_FAILURE) → 服务无 Restart → 长期离线` | SR-0003、SR-0010（叠加 SR-0008 崩溃路径） |
| CHAIN-4 本地提权 | `普通用户可写配置路径 → 写入 dhcp-script → root 服务认证成功 → system() → root 命令执行` | SR-0006（可叠加 SR-0007 的 pidfile 路径） |
| CHAIN-5 root 内存破坏 | `超长用户名/口令（配置或命令行）→ computePwd 越界 24 字节 / hash_md5_pwd 越界 1 字节 → 无加固构建下控制流劫持` | SR-0004、SR-0010 |

---

## 6. 重要的负向证据（已检查、未发现问题）

- **无可疑外联**：网络相关调用仅 `AF_PACKET`(0x888e) 原始套接字、`NETLINK_ROUTE`（本机内核路由）与用于 ioctl 的 `AF_INET/SOCK_DGRAM`；未发现 HTTP/TLS/DNS 客户端、硬编码 C2 地址、遥测或上传通道（NW-001 未命中）。
- **无持久化机制**：未发现 cron/systemd 单元/rc 脚本/开机项写入；唯一系统修改是安装期的 `systemctl enable`（运维显式执行）与 `SIOCSIFFLAGS` 混杂标志操作。
- **无动态加载/插件外挂**：无 `dlopen`/`dlsym`；插件全部编译期链接并需命令行显式 `--module` 选择。
- **无口令日志输出**：所有 `PR_*` 调用点均未把 `EAP_CONFIG.password` 写入日志（泄露来自 SR-0002 的越界读取，而非显式打印）。
- **无隐蔽指令通道**：Keep-Alive 心跳仅发送由服务端 echo key 派生的数值（`rjv3_send_new_keepalive_frame()`），不携带本地文件内容，且无远程命令解析（NW-004 未命中）。
- **GBK 转换表边界安全**：`util/gbconv.c` 的 `table` 恰为 24576 项，与 `gbk_to_index()` 的最大值 `0x5FFF` 一致（此前提交的边界检查有效）；且默认构建使用 iconv，不走该路径（`ENABLE_GBCONV := false`）。
- **MD5 实现为标准 RSA 参考实现**：常量、填充与轮函数与公开参考实现一致，未发现削弱或后门。
- **无 AI/Agent/MCP 组件**：不存在提示注入、工具投毒、委派身份等 SR-AG 类问题（该域不适用）。
- **工作区未被修改**：审查期间只做只读检查，仓库保持干净。

---

## 7. 修复计划

### 7.1 立即缓解（不改代码）

- 把接入网视为不可信：使用**一次性/专用账号**，禁止复用重要口令（针对 CHAIN-1）。
- `chmod 600 /etc/minieap.conf`，确认 `/var/log/minieap.log` 为 `600`；避免使用 `--save`；改用口令文件/交互输入替代 `-p`。
- 服务单元加 `Restart=always` + `RestartSec=5`，并考虑 `User=` + `AmbientCapabilities=CAP_NET_RAW` + `--fake-serial`。
- 校验部署中配置文件属主为 root 且组/其他不可写（针对 SR-0006）。

### 7.2 代码/配置修复（按优先级）

1. `parse_rjv3_buf_to_prop_list()`：长度与剩余缓冲比对、拒绝负长度、检查调用方返回值（SR-0002）。
2. `computePwd()`/`hash_md5_pwd()`：边界安全的缓冲与长度上限（SR-0004）。
3. 状态机：校验帧长与源/目的 MAC，不要用 `exit()` 处理可被远端触发的错误（SR-0003）。
4. `pid_lock` 安全打开 + PID 校验（SR-0007）；`getifaddrs`/resolv 判空（SR-0008）。
5. 凭据与文件权限：口令文件/交互输入、`O_CREAT|0600`、`explicit_bzero`（SR-0005）。
6. `dhcp-script` 改 `posix_spawn` + 启动期配置权限校验（SR-0006）。

### 7.3 依赖/工具链修复

- 编译加固：`-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now`，并确认自定义链接脚本不影响 RELRO（SR-0010）。
- 补齐 vendored 代码许可证头与出处、加入 MD5 归属声明、发布校验和/签名（SR-0011）。
- `make` 前对源码做完整性校验，隔离构建（SR-0012）。

### 7.4 Agent 策略修复

- 不适用：本项目不含 Agent/LLM/MCP 组件。

### 7.5 验证与回归

- 引入 ASan/UBSan + libFuzzer 目标（`parse_rjv3_buf_to_prop_list`、状态机 recv handler），把本报告中的合成报文写成固定用例。
- 新增断言测试：配置文件/日志权限位、48 字符用户名、重复 EAP 报文下的存活、pidfile 符号链接处理。
- 建议把 SR-0002/SR-0003/SR-0004 上报上游 `updateing/minieap`（本仓库为其 fork，HEAD 停留在 2023-09-21）。

---

## 8. 框架对照

以下为支撑性参考（非认证结论），均带版本：

| 发现 | 参考 |
| --- | --- |
| SR-0001、SR-0002、SR-0004 | OWASP ASVS 5.0.0（密码学、输入验证与解析、错误处理与日志章节）；CWE-125 / CWE-121 / CWE-798（用于缺陷归类，非正式映射） |
| SR-0003、SR-0008 | OWASP ASVS 5.0.0（错误处理与日志、拒绝服务防护章节） |
| SR-0005、SR-0006、SR-0007 | NIST SP 800-218 SSDF 1.1（PW 组：安全实现与审查；RV 组：漏洞响应）；OWASP ASVS 5.0.0（凭据存储与文件权限章节） |
| SR-0011、SR-0012 | SLSA 1.2（来源与构建溯源缺口）；NIST SP 800-218 SSDF 1.1（PW.4 复用软件组件的审查） |
| SR-0013 | OWASP ASVS 5.0.0（数据最小化与隐私相关章节） |

---

## 9. 局限与假设

- **未做动态验证**：未编译、未运行、未做 ASan/Valgrind 实测；所有结论基于静态代码与数据流推理（证据等级 E1/E2，已在各项 Confidence 中标注）。
- **平台差异**：审查主机为 Windows，未能在 Linux 上复现抓包行为；`sockraw`/`libpcap`/`bpf` 三种实现仅静态审查。
- **以太网最小帧长假设**：SR-0002 的可利用性基于“帧长可 ≥28 字节，且短帧会被垫充到 60 字节”的正常以太网行为；更短的帧（<40 字节）在真实链路上会被垫充，故 EAP 头部/MD5 种子路径的越界读更偏向理论性（已并入 SR-0002，未单列）。
- **上游与外部信息不可用**：网络受限，未核实 `updateing/minieap` 上游是否已修复、未获取 MentoHUST 许可证原文、未查询 CVE 历史；SR-0011 的许可证兼容性结论为 Medium 置信度。
- **未审查内容**：`.git` 历史对象未逐一审计（仅查看提交标题与工作区状态）；未审计 `LICENSE` 全文之外的第三方许可证文本；未在真实校园网/锐捷服务端验证协议行为。
- **未执行的操作**：未安装依赖、未修改源码、未提交、未联网、未对任何真实凭据或主机进行测试。

---

## 附录 A：发现索引

| ID | 标题 | Severity | Confidence | Domain | Lifecycle |
| --- | --- | --- | --- | --- | --- |
| SR-0001 | 同网段攻击者可冒充认证服务器并还原出口令明文 | High | High | SR-AS | runtime |
| SR-0002 | RJv3 属性长度未校验导致远程堆越界读取 | High | High | SR-AS | runtime |
| SR-0003 | 少量伪造报文即可远程终止客户端且不会自动恢复 | Medium | High | SR-AS | runtime |
| SR-0004 | 长用户名/口令导致栈缓冲区溢出 | Medium | High | SR-AS | runtime |
| SR-0005 | 口令以明文出现在命令行、配置文件和日志目录中 | Medium | High | SR-ID | runtime, install, uninstall |
| SR-0006 | 配置驱动的 root 命令执行（dhcp-script → system()） | Medium | High | SR-HP | runtime, install |
| SR-0007 | PID 文件符号链接/内容注入风险 | Low | High | SR-HP | runtime |
| SR-0008 | getifaddrs/resolv.conf 指针未判空导致崩溃 | Low | High | SR-AS | runtime |
| SR-0009 | 卸载不清理含口令的配置与日志 | Low | High | SR-LC | uninstall, cleanup |
| SR-0010 | 构建与运行加固缺失 | Low | High | SR-BL | build, deploy |
| SR-0011 | 内置第三方代码的出处、许可证与发布完整性 | Low | Medium | SR-SC | acquisition, dependency-resolution, build |
| SR-0012 | 构建期插件信任模型 | Informational | High | SR-BL | build |
| SR-0013 | 主机指纹信息被采集并发送给认证服务器 | Low | High | SR-DA | runtime |

## 附录 B：证据文件清单

| 文件 | 相关发现 |
| --- | --- |
| `eap_state_machine.c` | SR-0003（重试/同状态计数退出）、SR-0001（接受任意源 MAC 的 EAP 请求） |
| `packet_builder.c` | SR-0004（`hash_md5_pwd` 栈数组） |
| `config.c`、`include/config.h` | SR-0005（口令命令行/保存）、SR-0004（凭据长度上限） |
| `util/conf_parser.c` | SR-0005（`fopen(..., "w")` 权限）、SR-0006（以 root 解析任意路径配置） |
| `util/pid_lock.c` | SR-0007 |
| `util/net_util.c` | SR-0008（`ifa_addr` 判空）、SR-0013（DNS 采集） |
| `util/misc.c`、`util/packet_util.c` | SR-0002（`memdup` 越界读、`frame_duplicate` 精确堆块） |
| `packet_plugin/rjv3/packet_plugin_rjv3.c` | SR-0006（`system()`） |
| `packet_plugin/rjv3/packet_plugin_rjv3_priv.c` | SR-0001、SR-0002、SR-0008、SR-0013 |
| `packet_plugin/rjv3/packet_plugin_rjv3_prop.c` | SR-0002（TLV 解析边界） |
| `packet_plugin/rjv3/rjv3_hashes/checkV4.c` | SR-0001（口令异或）、SR-0004（栈溢出）、SR-0011（二进制常量块） |
| `Makefile`、`minieap.mk`、`append.mk` | SR-0005、SR-0009、SR-0010、SR-0012 |
| `minieap.service.in` | SR-0003、SR-0010 |
| `md5.c`、`rjv3_hashes/*` | SR-0011（许可证/出处） |

---

*本报告由静态代码审查生成，未执行任何动态测试；结论仅覆盖仓库中可见的源码、构建脚本与部署模板。*
