# Collector 权限模式与功能配置生命周期

[English](collector-mode-lifecycle.md) | 简体中文

本文记录 PerfLens `0.3.0` 的 Collector 首次部署、项目初始化、权限模式和功能配置
切换合同。

## 目标

PerfLens 继续提供两个明确、互斥的 Collector 权限模式：

| 模式 | 适用环境 | 权限边界 | 主机要求 |
| --- | --- | --- | --- |
| `cap_perfmon` | 常规 Linux 主机，推荐默认选择 | Python Broker 以专用 `perflens` 用户运行，只获得受限性能监控 capability | 主机策略必须允许该 capability 工作；Debian `perf_event_paranoid=3` 通常不适用 |
| `paranoid3_helper` | 必须保留 Debian `perf_event_paranoid=3` 的主机 | 普通用户客户端 → 非特权 Python Broker → 独立 Rust Helper；Helper 是 root 服务，但 capability 集被 systemd 限定 | 管理员必须明确确认扩大后的 root、`CAP_SYS_ADMIN`、`CAP_SYS_PTRACE` 风险 |

安装 DEB 只把两种模式需要的程序和模板放到系统中，不应自动选择模式、修改 sysctl、启动服务或扩大权限。

v0.3.0 提供两个相互独立的**功能配置**：

| 功能配置 | 采集能力 | 产品定位 |
| --- | --- | --- |
| `full_diagnostics` | `stat`、`record`、`sched`、`off_cpu`、`lock` | 主机通过全部前置检查时的新安装推荐项 |
| `cpu_only` | `stat`、`record` | 权限和证据面更小；已有 `0.2.0` 部署升级后的兼容配置 |

功能配置回答“允许采集哪些证据”，权限模式回答“哪个受限系统进程持有什么权限”。例如，
`full_diagnostics + paranoid3_helper` 需要现有 stat/record Helper 和独立 Trace Helper，
不能把这两个维度合并成第三种权限模式。

## `0.3.0` 首次部署体验

管理员使用一个入口完成首次选择：

```bash
sudo perflens-admin setup
```

`setup` 只用于尚未部署 Collector 的主机。如果系统策略已经存在，它会在修改系统前
停止，并明确引导管理员使用 `switch-mode`、`upgrade` 或 `update-policy`，不会拿默认
配置覆盖已有管理员策略。

交互式向导提供以下选择：

1. `cap_perfmon`：默认、权限更小；
2. `paranoid3_helper`：保留 `perf_event_paranoid=3`，需要风险确认；
3. 仅分析：不部署 Collector，只分析已有证据。

自动化部署可显式指定模式，且应先执行只读预检：

```bash
sudo perflens-admin setup --mode cap_perfmon --dry-run
sudo perflens-admin setup --mode cap_perfmon
```

`paranoid3_helper` 的正式部署必须额外传入：

```bash
sudo perflens-admin setup \
  --mode paranoid3_helper \
  --acknowledge-privileged-helper-risk
```

向导只生成和安装固定、可验证的 PerfLens 策略与 systemd unit。它不得修改 `perf_event_paranoid`，不得让 Agent、Skill、MCP 或 Python Broker 以 root 运行，也不得以 Helper 权限启动用户命令。
如果选择 `cap_perfmon` 时检测到 `perf_event_paranoid > 2`，预检会标记为不可用，正式
部署会在写入系统前拒绝，并提示改选 Helper、仅分析或由管理员单独审查内核策略。

## `v0.3.0` 两阶段向导

DEB 安装继续保持非交互和非激活，只在安装完成摘要中提示：

```text
下一步：运行 sudo perflens-admin setup
```

新安装的交互式向导首先只显示两个主要功能配置：

```text
1. 完整性能诊断（推荐）
   stat + record + sched + off_cpu + lock

2. 标准 CPU 调优
   stat + record；权限范围更小
```

向导先执行不加载 BPF、不写系统的只读检查。包内 Trace Helper 与内核 BTF 前置条件可用
时，完整配置显示为默认功能推荐项，同时明确提示部署后仍需真实短时验收；前置条件不足时，
向导必须把完整配置标为当前不可用并默认推荐 `cpu_only`，不得以 `full_diagnostics` 名义
静默部署部分功能。`analysis_only` 保留为第三个部署选择和失败回退，但不作为第三个功能
配置。

选择功能配置后，向导读取 `perf_event_paranoid`：值不大于 2 时默认推荐权限更小的
`cap_perfmon`；值大于 2 时明确标记该路径受阻并默认推荐主机兼容的
`paranoid3_helper`，但绝不修改该值。管理员仍可显式指定模式，但冲突选择必须在写系统前
拒绝；无法预读内核策略时由部署预检再次验证。非交互接口为：

```bash
sudo perflens-admin setup \
  --feature-profile full_diagnostics \
  --mode cap_perfmon \
  --dry-run

sudo perflens-admin setup \
  --feature-profile full_diagnostics \
  --mode paranoid3_helper \
  --acknowledge-privileged-helper-risk \
  --acknowledge-trace-risk
```

完整配置需要单独确认 trace 的调用路径、线程元数据、磁盘和采集开销风险；level 3
实现还需要现有 Helper 风险确认。现有 Rust Helper 继续只接受 `stat/record`，高级模式
交给拥有独立 unit、Socket、协议、策略和 spool 的 Trace Helper。PerfLens 仍不修改
`perf_event_paranoid`，也不让 Agent、Skill、MCP 或 Python Broker 以 root 运行。

独立 Trace Helper 的 capability 随权限模式固定渲染：`cap_perfmon` 使用
`CAP_BPF CAP_PERFMON`；Debian level 3 会提前拒绝 tracepoint `perf_event_open`，所以
`paranoid3_helper` 使用 `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN`。后一项只存在于管理员明确
确认 `--acknowledge-trace-risk` 后创建的独立 Trace Helper unit，不会进入现有 Helper、
Python Broker、MCP、Skill 或 Agent。

两个权限模式的完整配置都使用该独立 Trace Helper 和包内固定 eBPF。后端在内核中先按
授权 TGID/TID 过滤，再把 target-only NDJSON 写入私有 spool；它不使用 stock `perf -p`
冒充完整调度证据，也不调用或回退到 `perf -a`/等价全 CPU 采集。

## 项目初始化体验

Collector 是主机级服务，`perflens init` 是项目级集成。二者只需要分别执行一次：

```bash
cd /绝对路径/项目
perflens init
```

项目初始化应安全读取 `/etc/perflens/collector.toml`，自动识别已部署模式，并据此给 Codex/Claude Code MCP 配置正确的只读产物目录：

- `cap_perfmon` → `/var/lib/perflens`
- `paranoid3_helper` → `/var/lib/perflens-helper`

如果系统没有部署 Collector，则新项目初始化回退到 `cap_perfmon`，但不会部署或启动它。已有项目执行 `perflens init --update` 时会保留其已记录的候选模式，避免 MCP 与尚未部署的候选资产互相矛盾。如果系统策略存在却所有者、权限、大小或内容不安全，初始化必须失败并提示修复，不能静默猜测。

普通 `perflens init` 已自动读取已部署功能配置，生成一致的 MCP
模式白名单和证据根目录。项目用户不需要记住 `--feature-profile` 或 Collector 权限参数；
只有主机管理员通过 `setup/switch-profile/switch-mode` 改变系统状态。

高级用户仍可使用 `--collector-privilege-mode` 显式准备某种模式的部署资产。如果主机已经部署 Collector，显式值只要与已部署模式冲突就必须报错；`--prepare-collector` 也不能绕过这一检查，避免先把 MCP 指向尚未启用的证据目录。请先由管理员执行 `switch-mode`，再在项目中运行 `perflens init --update`。只有主机尚未部署 Collector 时，才能显式生成某一模式的首次部署资产。

## 当前权限模式切换

同一台主机同一时刻只能激活一种模式。切换前必须预检：

```bash
sudo perflens-admin switch-mode cap_perfmon --dry-run
sudo perflens-admin switch-mode paranoid3_helper --dry-run
```

正式切换：

```bash
sudo perflens-admin switch-mode cap_perfmon

sudo perflens-admin switch-mode paranoid3_helper \
  --acknowledge-privileged-helper-risk
```

切换是主机级事务：

1. 验证当前策略、受管 unit、目标模式、程序路径和主机前置条件；
2. 停止旧服务；
3. 原子替换策略和受管 unit；
4. 只启动目标模式需要的服务；
5. 完成带身份校验的 Unix Socket 健康检查；
6. 任一步失败时恢复旧策略、旧 unit 和旧服务。

所有正式的 `deploy`、`switch-mode`、`upgrade`、`update-policy` 和 `undeploy` 写操作都通过固定、权限收紧的主机级事务锁串行执行，避免两个管理员命令交错覆盖快照。`/etc/perflens/collector.toml` 必须严格由 root 所有；普通用户拥有的 `0600` 文件只可作为首次部署或策略更新的待审查候选，不能冒充已部署策略。

切换不得删除或迁移 `/var/lib/perflens`、`/var/lib/perflens-helper` 中的证据。切换到 `cap_perfmon` 时，如果当前 `perf_event_paranoid > 2`，预检应明确标记为不可用，正式切换应拒绝；PerfLens 仍不得自动降低 sysctl。

切换成功后，已初始化项目执行：

```bash
cd /绝对路径/项目
perflens init --update
```

如果目标模式已经生效但安装包内的受管 systemd 模板更新了，`switch-mode` 不会借机
改写文件，而会提示执行 `sudo perflens-admin upgrade`；模式切换与版本升级保持为两个
边界清楚的操作。

有一个例外：策略已经是 `cap_perfmon`，但系统中仍残留带 PerfLens 托管标记的 Helper
unit 时，同模式 `switch-mode cap_perfmon` 会返回修复计划，正式执行后停止并移除残留
Helper；`upgrade` 也会完成同样的收敛。修复失败会恢复原文件并保持残留 Helper 停止，
不会为了回滚重新扩大特权边界；Broker 会恢复运行。普通模板漂移仍由 `upgrade` 处理，
不会混入模式切换。

模式切换失败且旧模式恢复成功时，命令仍以失败退出，但结构化错误的
`details.rollback_performed` 为 `true`；恢复也失败时为 `false`。成功产物不再包含一个
永远无法到达的回滚字段。

该命令重新检测主机模式并同步 MCP 允许读取的 spool。未初始化的项目不受影响，也不会自动加载 PerfLens Skill。

## `v0.3.0` 功能配置切换

功能配置使用独立命令，不能通过修改 `allowed_modes` 或借用 `switch-mode` 绕过：

```bash
sudo perflens-admin switch-profile full_diagnostics --dry-run
sudo perflens-admin switch-profile full_diagnostics --acknowledge-trace-risk

sudo perflens-admin switch-profile cpu_only --dry-run
sudo perflens-admin switch-profile cpu_only
```

`switch-profile` 必须复用同一个主机事务锁，验证策略、受管 unit、目标配置和主机能力，
展示确定性差异，原子更新 trace 拓扑并完成认证健康检查。失败恢复原策略、unit 和服务。
切回 `cpu_only` 时停止并禁用 Trace Helper，但保留管理员配置和全部证据。

完整配置切换成功只证明拓扑健康。管理员还必须以普通用户运行
`perflens accept-collector --authorize-host-acceptance`；该命令依次验证 `sched/off_cpu/lock`
的实质目标证据、确定性分析和 verifier，不能用空事件或仅服务存活代替真实验收。

已启用完整配置时再运行 `switch-mode`，同一事务必须把 Broker、现有 Helper 和 Trace
Helper 收敛为目标权限模式对应的拓扑。任何切换均不删除或迁移 spool。切换完成后，
已经初始化的项目运行一次 `perflens init --update` 同步 MCP 配置。

从 `0.2.0` 安装新包只升级程序和可信模板：已部署主机保持 `cpu_only`，不得自动生成
trace 策略、启动 Trace Helper 或扩大权限。管理员审查后显式执行
`switch-profile full_diagnostics` 才能启用完整配置。

## 兼容与安全边界

- `perflens-admin deploy --config ...` 继续保留，适合审查过自定义 TOML 的高级部署。
- `perflens-admin update-policy` 只修改同一模式内的策略，不负责切换模式。
- `perflens-admin upgrade` 只升级已部署服务文件并保留管理员策略，不负责切换模式。
- `switch-profile` 只切换功能配置，不能借机切换授权 UID、spool 或权限模式。
- 旧的 `--acknowledge-cap-sys-admin-risk` 参数继续作为兼容别名，但新文档使用 `--acknowledge-privileged-helper-risk`。
- 安装、初始化、预检和切换都不能静默修改 sysctl、文件 capability 或未知 unit。
- 只允许替换带 PerfLens 托管标记且身份、所有权和权限通过验证的文件。
- 正式管理员写操作必须持有固定事务锁；只读预检不修改锁定范围内的系统状态。

## 验收条件

权限模式只说明部署和安全边界，不代表所有性能采集模式已经成熟。当前事实基线与
`sched/lock/off_cpu` 的分阶段扩展门槛见
[《采集能力扩展路线图》](collector-capability-roadmap.zh-CN.md)。

- 首次向导的三种选择均有 CLI 测试；非交互环境可以用 `--mode`。
- `perflens init` 能识别两种安全的已部署策略；不安全策略、显式冲突和无策略回退均有测试。
- 两个方向的切换都有 dry-run、成功、重复执行、风险确认和失败回滚测试。
- 残留 Helper 收敛、固定配置 root 所有权、管理员事务锁和回滚状态均有拒绝或恢复测试。
- 切换不得遗失管理员的其余策略字段，不得删除两个 spool。
- `paranoid3_helper` 仍通过 Rust Helper 独立校验协议、PID、事件、时限、频率、输出和固定 spool。
- Python lint、类型检查、完整测试、覆盖率门槛，Rust fmt/clippy/test，以及 DEB smoke test
  全部通过后，才可发布下一版本；新能力按 `v0.3.0` 路线图验收，不能移动已经公开的标签。
- v0.3.0 发布门还必须覆盖两个功能配置、环境动态推荐、非 TTY 参数缺失、两类风险确认、
  两个权限模式乘两个功能配置的组合、profile 切换回滚和证据保留。
- DEB 首次安装和从 `0.2.0` 升级都必须保持服务非激活；升级不得自动从 `cpu_only` 扩大到
  `full_diagnostics`。
