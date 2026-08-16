# PerfLens v0.3.x Collector 与用户态锁能力路线图

简体中文 | [English](collector-capability-roadmap.md)

状态：**v0.3.0 源码实施中；尚未发布**

最后审计：2026-08-16，基于当前 `main` 的 v0.3.0 预发布实现

候选目标版本：`v0.3.0`、`v0.3.1`

本文是实现、测试和发布说明的设计合同，严格区分“`0.2.0` 已发布”“v0.3.0 已在源码
实现但等待发布门禁”和“v0.3.1 计划实现”。源码存在不等于已发布；只有完整 CI、Rust、
DEB、升级/回滚和真实 Debian 主机验收通过后，v0.3.0 才能写成稳定发布能力。

当前源码已经完成 v0.3.0 的版本化 Trace 合同、目标内核过滤 Rust Trace Helper、三类
确定性分析器和 verifier、独立策略/Socket/spool、`setup/switch-profile/status/upgrade/
undeploy` 事务，以及 `accept-collector` 三模式真实验收。仍待本路线图末尾的完整发布门禁；
v0.3.1 四类用户态锁 Adapter 尚未实现。

## 1. 决策摘要

PerfLens 按两个版本扩大 Linux 性能诊断边界：

1. **`v0.3.0` 完成通用等待诊断。** 在保留 `stat/record` CPU 调优闭环的基础上，正式完成
   `sched`、`off_cpu` 和 `lock` 的确定性分析、受控采集、安装向导和真实主机验收。
2. **功能配置与权限模式分离。** `full_diagnostics/cpu_only` 决定开放哪些证据能力；
   `cap_perfmon/paranoid3_helper` 决定系统服务如何获得权限。两者不是同一组模式。
3. **完整诊断是新安装的推荐配置，但不是无条件自动启用。** DEB 安装不交互、不启动服务；
   管理员运行 `sudo perflens-admin setup`，经过主机预检、明确选择和风险确认后才部署。
4. **现有 Rust Helper 永远保持 `stat/record`。** `perf_event_paranoid=3` 下的高级 trace
   由新的独立 Trace Helper 承担，不把 trace 协议和权限塞进现有 Helper。
5. **`v0.3.1` 增加四类正式用户态锁 Adapter。** 覆盖 C/C++ pthread、Java JFR、
   CPython 锁和 Go mutex/block profile；自定义、内联、无探针或 lock-free 实现必须准确
   报告覆盖缺口，不能宣称任意程序的所有锁都可见。
6. **先证明证据语义，再扩大权限。** 每个分析器先通过冻结输入、Golden、守恒和 verifier，
   再进入实时采集、安全和真实主机门禁。

## 2. 当前 `0.2.0` 事实基线

### 2.1 当前正式能力

| 层 | `stat` / `record` | `sched` / `lock` / `off_cpu` |
|---|---|---|
| 公共 Python 类型与 CLI/MCP | 已表达并正式使用 | 已有原始入口，不等于正式支持 |
| 默认 Collector 策略 | 允许 `record, stat` | 默认拒绝 |
| `cap_perfmon` Python Collector | 固定 argv、时限和产物 | 能构造固定原始命令，但没有专用分析闭环 |
| `paranoid3_helper` | Rust 协议仅允许 `Record/Stat` | 严格拒绝 |
| 确定性分析 | stat 指标；record 热点、调用路径、源码和完整性验证 | 缺少稳定的区间、延迟和等待 Artifact |
| 当前成熟度 | **当前正式** | **当前实验入口** |

当前正式闭环为：

```text
精确工作负载授权
        ↓
短时 stat（硬件或软件事件）
        ↓
需要调用栈时 record（cycles 或 cpu-clock）
        ↓
原始证据哈希、事件来源和转换身份绑定
        ↓
热点、调用路径、源码和 EvidenceQuality
        ↓
正确性测试 + 同工作负载、同事件来源 A/B
```

它足以对 CPU 饱和、算法复杂度和函数热点做有价值的调优。硬件 PMU 不可用时，软件
降级仍能定位 on-CPU 热点，但不能得出 IPC、硬件缓存未命中或分支未命中结论。

### 2.2 当前不足

| 问题 | 当前边界 | v0.3.x 方向 |
|---|---|---|
| 线程长期 runnable | 只有活动计数，缺少等待区间和分位数 | `sched` |
| CPU 不高但墙钟时间长 | 缺少切出、唤醒和重新运行配对 | `off_cpu` |
| 内核锁和 futex 等待 | 原始证据不等于稳定 owner/waiter 分析 | `lock` |
| C/C++ 用户态锁快路径 | futex 只能看到部分慢路径 | Native Adapter |
| JVM 监视器和 park | 通用 perf 不能表达完整 JVM 语义 | JFR Adapter |
| GIL 与 Python 应用锁 | 两者语义不同，不能从符号名称互推 | CPython Adapter |
| Go runtime 锁和阻塞 | 应保留 runtime profile 的采样语义 | Go pprof Adapter |
| heap、I/O 请求、GPU、跨主机 APM | 不在本路线图边界 | 独立后续 Adapter |

较少的 context-switch、migration 或 page-fault 只代表本次观察到这些事件较少，不能证明
不存在 I/O 等待、锁竞争、分配抖动或内存压力。

## 3. v0.3.0 安装向导与模式模型

### 3.1 DEB 安装边界

`perflens` 和 `perflens-collector` DEB 继续只安装程序、模板和文档。安装过程：

- 不弹交互问题；
- 不生成管理员策略；
- 不启动或启用服务；
- 不修改 sysctl、文件 capability 或用户项目；
- 只在安装完成摘要中提示下一步运行 `sudo perflens-admin setup`。

这样无人值守升级和镜像构建不会意外扩大主机权限。

### 3.2 两个主要功能配置

`v0.3.0` 的交互式 `setup` 首先展示：

```text
请选择 PerfLens 功能配置：

1. 完整性能诊断（推荐）
   stat + record + sched + off_cpu + lock

2. 标准 CPU 调优
   stat + record；权限范围和证据面更小
```

- `full_diagnostics` 是主机通过全部前置检查时的新安装推荐项。
- `cpu_only` 是最小权限配置，并且是所有 `0.2.0` 已部署主机升级后的兼容配置。
- 如果完整配置缺少 tracefs、内核事件、perf 支持或安全前置条件，向导必须把它标为
  “当前主机不可用”，动态推荐 `cpu_only`，不能静默部署一个不完整的“完整配置”。
- `analysis_only` 继续作为高级自动化值和失败回退，不占两个主要功能选项。

计划中的非交互接口为：

```bash
sudo perflens-admin setup \
  --feature-profile full_diagnostics \
  --mode cap_perfmon \
  --dry-run
```

这些参数已经进入 v0.3.0 源码，但 `0.2.0` 安装包没有这些接口；在 v0.3.0 发布门禁完成
前只能用于源码/本机构建验收，不能当作稳定发布命令。

### 3.3 权限实现自动推荐

功能配置之下仍有两个互斥的 Collector 权限模式：

| 权限模式 | 推荐条件 | `cpu_only` | `full_diagnostics` |
|---|---|---|---|
| `cap_perfmon` | 主机策略允许专用 capability，真实短时预检通过 | Python Broker 执行 stat/record | Broker + 独立 Trace Helper；Trace Helper 限定为 `CAP_BPF CAP_PERFMON` |
| `paranoid3_helper` | 必须保留 Debian `perf_event_paranoid=3` | Broker → 现有 Rust Helper | 现有 Helper 负责 stat/record；独立 Trace Helper 限定为 `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN` |

向导根据实际主机检查给出推荐，但管理员仍可用 `--mode` 显式选择。PerfLens 不自动降低
`perf_event_paranoid`。如果显式选择与主机事实冲突，dry-run 和正式部署都必须在写系统前
拒绝。

选择 `full_diagnostics` 必须确认 trace 的调用路径、线程元数据、磁盘和采集开销风险；
选择 `paranoid3_helper` 还必须单独确认现有高权限 Helper 风险：

```bash
sudo perflens-admin setup \
  --feature-profile full_diagnostics \
  --mode paranoid3_helper \
  --acknowledge-privileged-helper-risk \
  --acknowledge-trace-risk
```

Debian level 3 会在常规 `CAP_PERFMON` 判断前拒绝 tracepoint 的 `perf_event_open`，因此只有
`paranoid3_helper + full_diagnostics` 的独立 Trace Helper 额外获得受 systemd BoundingSet
和 AmbientCapabilities 限定的 `CAP_SYS_ADMIN`。该 capability 不会授予 Python Broker、
MCP、Skill 或 Agent；`cap_perfmon` 路径也不会获得它。管理员的两个风险确认分别覆盖现有
stat/record Helper 和新增 Trace Helper，PerfLens 仍不修改 sysctl。

### 3.4 安装后的配置切换

功能配置与权限模式分别切换：

```bash
sudo perflens-admin switch-profile full_diagnostics --dry-run
sudo perflens-admin switch-profile full_diagnostics --acknowledge-trace-risk

sudo perflens-admin switch-profile cpu_only --dry-run
sudo perflens-admin switch-profile cpu_only
```

`switch-profile` 已在 v0.3.0 源码实现，并遵守以下事务合同：

1. 验证当前策略、受管 unit、目标配置和主机能力；
2. 生成可审查的确定性差异和命令计划；
3. 原子更新独立 trace 策略和服务；
4. 完成认证健康检查；
5. 失败时恢复原策略、unit 和服务；
6. 从完整切回标准时停止 Trace Helper，但保留所有证据和管理员配置。

现有 `switch-mode` 继续只切换 `cap_perfmon/paranoid3_helper`。在完整配置下切换权限模式时，
同一次受管事务必须把对应的 Broker、Helper 和 Trace Helper 拓扑收敛到目标状态。

从 `0.2.0` 升级不得自动创建 trace 策略、启动 Trace Helper 或扩大 allowed modes。管理员
必须显式运行 `switch-profile full_diagnostics`。项目侧继续只需运行 `perflens init`；它
安全读取已部署的权限模式和功能配置，为 Codex/Claude Code 生成一致的 MCP 配置。

## 4. v0.3.0 Trace 架构与安全边界

### 4.1 进程与数据流

```text
普通用户 Agent / Skill / MCP
              │ typed plan，明确 PID/工作负载授权
              ▼
        非特权 Python Broker
                    │ 私有 Trace Helper Socket
                    ▼
        独立 Rust Trace Helper + 包内固定 eBPF 程序
                    │ 在内核中按授权 TGID/TID 过滤
                    │ 私有 target-only NDJSON（不是 perf.data）
                    ▼
        固定流式解析/脱敏 → TraceEvidence → 确定性分析 + verifier
```

现有 Rust Helper 继续只接受 `Record/Stat`。新的 Trace Helper 必须拥有独立：

- 二进制和 systemd unit；
- 私有 Unix Socket 和内部服务组；
- Rust 协议与 JSON Schema；
- 管理员策略和固定私有 spool；
- capability 审计、风险确认、升级、回滚和卸载流程。

两个权限模式的高级采集都使用独立 Trace Helper；`cap_perfmon` 不让 Python Broker 承担
全 CPU trace。Helper Socket 不得向普通用户开放。目标内私有 trace 只进入私有 spool；公开给 MCP 的派生产物
必须先经过目标范围、大小、事件、丢失和隐私检查。

stock `perf record -p PID` 无法完整观察外部唤醒者和目标 switch-in，因此不能作为稳定的
`sched/off_cpu` 后端。PerfLens 不调用也不静默回退到 `perf -a` 或等价的 `-C 0-N` 全 CPU
采集。固定包内后端必须在任何事件或目标外元数据进入用户态 spool 前完成内核目标过滤。

### 4.2 固定安全边界

- 只接受绑定 UID、PID/TID、进程启动时间、模式和过期时间的短期单次计划；
- 不允许 `perf -a`、system-wide 目标、任意 tracepoint、任意 perf 参数或任意输出路径；
- 不允许 workload 命令、环境变量、shell 或以 Helper 权限启动用户代码；
- 每种模式使用固定事件和 argv 白名单，单次默认最多 10 秒、64 MiB、一个并发 worker；
- 目标外任务元数据必须隔离或脱敏，不能写入普通用户可读 spool；
- 事件丢失、未配对或截断超过分析门槛时返回 `partial` 或失败；
- 新 Trace Helper 的 capability 不得超过经过审计的模式化集合：`cap_perfmon` 使用
  `CAP_BPF CAP_PERFMON`，`paranoid3_helper` 因 Debian level 3 的 tracepoint 拒绝使用
  `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN`；不足时失败关闭，不能加入不受限 root，也不能让
  Python Broker 获得 `CAP_SYS_ADMIN`；
- Trace 路径不产生或公开 `perf.data`；record Profile 仍由固定系统 perf Adapter 转换，
  PerfLens 不直接解析其二进制格式。

## 5. v0.3.0 确定性分析合同

所有新 Artifact 都需要 `schema_version`、输入 SHA-256、转换器版本/路径/argv、采集身份、
事件时钟和单位、丢失/乱序/重复/未配对数量、`quality_status`、允许/禁止结论、内容摘要、
转换指纹和独立 verifier。

`v0.3.0` 固定以下公共产物名称；以后改名或改变字段语义必须走 Schema 迁移，不能让 MCP
在同一 `schema_version` 下猜测不同结构：

- `TraceEvidenceArtifact`：经过目标过滤、规范化和有界化的 trace 事件及来源 manifest；
- `SchedulerAnalysisArtifact`：运行区间和 runnable 延迟分析；
- `OffCpuAnalysisArtifact`：blocked/sleeping、wakeup 和重新运行区间分析；
- `LockAnalysisArtifact`：内核锁及通用 futex/用户态等待候选；
- `TraceAnalysisVerificationArtifact`：独立重算哈希、事件数量、区间守恒和质量结论。

`TraceEvidenceArtifact` 不包含私有路径、目标外身份或原始地址，只引用不可变私有
target-only NDJSON 的 SHA-256、大小、采集 ID、目标身份和固定转换 manifest，并保存公开
规范化 NDJSON 的 SHA-256。转换器
输出必须先写入新临时文件、完整验证后原子发布；任何解析失败都保留有界原始诊断，不能
覆盖源 Profile。

### 5.1 SchedulerAnalysisArtifact

至少输出每线程运行时间、runnable 等待、上下文切换、迁移、平均值、p50/p95/p99/最大值、
样本数量和最严重延迟区间。缺失 wakeup/switch-in 配对时不得输出伪造延迟；低样本分位数
必须标记不稳定。

### 5.2 OffCpuAnalysisArtifact

基于 switch-out、wakeup、switch-in 重建完整区间，并在证据允许时分离 blocked/sleeping
时间与 runnable 时间。记录目标 TID、任务状态、切出调用栈、唤醒者和完整性。磁盘、网络、
锁或定时器只能作为候选类别，不能仅凭函数名确认根因。

### 5.3 LockAnalysisArtifact

聚合底层证据真实提供的竞争次数、等待分布、稳定匿名锁 ID、owner/waiter 和调用路径。
持锁时间只在 acquire/release 可可靠配对时输出；没有 owner 证据时不得猜测。`v0.3.0`
把 futex/off-CPU 关联标为用户态锁等待候选，不把它伪装成特定语言锁的完整视图。

`TraceAnalysisVerificationArtifact` 至少逐项返回 `passed/failed/skipped`：原始证据身份、
转换 manifest、目标范围、事件计数、时间区间、分析聚合守恒、丢失/截断一致性和 Agent
可见内容摘要。任一安全或守恒项目失败时，MCP 不得把分析交给 Agent 作为可用证据。

## 6. v0.3.0 实施里程碑

1. **源码已完成：** 冻结 `stat/record` 基线和现有策略兼容性。
2. **源码已完成：** 固定目标过滤事件 IR、Schema、Golden 和 verifier。
3. **源码已完成：** `sched/off_cpu/lock` 确定性分析、守恒和拒绝路径。
4. **源码已完成：** 私有协议、独立 Rust Trace Helper、BPF 目标过滤和隐私检查。
5. **源码已完成：** `setup/switch-profile/status/accept-collector`、MCP 路由和生命周期回滚。
6. **发布前待完成：** 同步 Skill/中英文文档并冻结用户体验。
7. **发布前待完成：** 完整 Python 覆盖率、Rust fmt/clippy/test/audit/deny 和跨语言协议矩阵。
8. **发布前待完成：** 两个 DEB 的安装、升级、切换、卸载、非激活和可复现 smoke test。
9. **发布前待完成：** Debian 12/13 上四组合真实验收，含外部唤醒、switch-in、动态线程、
   锁竞争、事件丢失、跨 UID 拒绝和公开字节隐私扫描。

Skill 的默认证据选择为：

```text
短时 stat
   ├─ CPU 密集且需要栈 → record
   ├─ runnable/迁移异常 → sched
   ├─ CPU 不高但墙钟长 → off_cpu
   └─ 明确竞争候选 → lock
```

即使安装了完整配置，也不能在一次请求中无差别运行所有采集。Skill 只能在用户已批准的
精确工作负载和管理员策略内选择最小必要证据，不能自动扩大 PID、命令、时长或权限。

## 7. v0.3.1 用户态锁 Adapter

### 7.1 “完整覆盖”的产品含义

用户态锁不是做不到，而是不存在一个通用 perf 命令一次覆盖所有语言和实现。`v0.3.1`
的“完整覆盖”指四类正式运行时 Adapter 都有能力检测、采集、规范化分析和质量说明，
而不是声称任意自定义锁、lock-free 算法或不可观察快路径都能被看见。

`v0.3.1` 固定以下公共产物名称：

- `RuntimeAdapterCapabilityArtifact`：运行时、版本、Adapter/后端版本、可用状态、支持的
  锁和事件、所需外部工具、是否需要启动插桩/附加/特权、快路径可见性和限制；
- `RuntimeLockEvidenceArtifact`：目标身份、来源 manifest、规范化事件、采样/阈值配置、
  丢失/截断计数和输入哈希；
- `RuntimeLockAnalysisArtifact`：按锁、线程、调用路径和等待类型聚合的结果及证据质量；
- `RuntimeLockAnalysisVerificationArtifact`：独立复核输入身份、转换 manifest、事件数量、
  等待/持有守恒、聚合和 Agent 可见内容摘要。

每条规范化事件使用严格枚举：

```text
event_kind = wait_begin | wait_end | acquire | release |
             park | unpark | sampled_contention
measurement_semantics = exact | thresholded | sampled | cumulative
```

公共字段至少包括 runtime、backend、PID/TID、目标进程启动身份、`lock_kind`、artifact 内
稳定匿名 `lock_id`、waiter、仅在来源真实提供时出现的 owner、`timestamp_ns`、可选
`duration_ns`、`stack_id`、符号/源码、采样率或周期、事件阈值、丢失/截断、快路径
可见性、覆盖范围、allowed/forbidden conclusions 和转换 manifest。

`lock_id` 按同一 Artifact 中第一次出现的规范顺序生成，不公开原始地址，也不允许跨
Artifact 推断为同一把锁。抽样次数不得伪装成精确竞争次数，累计 profile 不得伪装成
事件序列；缺少 acquire/release 配对时不得声称精确持锁时间。严格解析器必须拒绝未知
字段、越界帧、非法/不匹配 PID、负数或逆序时间、重复事件 ID、非有限权重、未知枚举、
超限锁/TID/调用栈基数和不守恒聚合。

### 7.2 C/C++ Native Adapter

- 正式支持动态链接 glibc/pthread 的 mutex、rwlock 和 condition variable；
- 对 PerfLens 启动的工作负载提供显式选择、以目标普通用户运行的插桩/拦截方案；
- 支持导入已有 USDT/uprobe 证据，并记录库版本、符号和 ABI 能力；
- 静态链接、内联、自定义原子锁、自旋锁、无竞争快路径、无符号/未知 ABI 和不兼容包装器
  必须报告 `partial/unsupported`；
- 实时 eBPF/uprobe 默认关闭，也不并入现有 Helper 或 Trace Helper；如果验收证明必须使用
  新权限，则另建服务、策略、Socket、卸载流程和管理员风险确认。

### 7.3 Java Adapter

- 首选用户安装的 JDK Flight Recorder，正式兼容 JDK 17、21、25 LTS；
- 使用随 PerfLens 版本管理的固定 JFR 配置，至少分析 `jdk.JavaMonitorEnter`、
  `jdk.JavaMonitorWait`、`jdk.ThreadPark`，并通过能力发现选择运行时实际存在的虚拟线程
  相关事件；
- 保留每种事件的启用状态和时长阈值。JFR 默认模板可能只记录超过阈值的事件，因此未记录
  事件不能解释成“没有等待”，降低阈值还必须同时披露额外开销；
- async-profiler 是自动检测的可选增强后端，JVMTI 只提供受控导入接口；
- PerfLens 不在核心 DEB 中捆绑 JDK、async-profiler 或自制通用 JVMTI Agent。

事件名称和阈值语义以
[Oracle JFR 性能诊断文档](https://docs.oracle.com/en/java/javase/17/troubleshoot/troubleshoot-performance-issues-using-jfr.html)
为基线；Adapter 启动时仍必须从当前 JDK 的事件元数据确认，不能只按版本号猜测。

### 7.4 Python Adapter

- 正式支持 CPython 3.12/3.13 的 `threading.Lock`、`RLock`、`Condition` 和 `Semaphore`；
- 分别建模 GIL、CPython 内部锁和应用层 threading 锁，三者不能互相推断；
- CPython 3.13 free-threaded 构建单独识别，不输出传统 GIL 结论；
- DTrace/SystemTap/USDT 作为可选导入后端，并按 CPython 构建与版本报告兼容性；
- C 扩展内部锁、自定义原子锁和未经过 Adapter 的锁明确标记不可见或部分覆盖。

CPython 探针名称和参数属于实现细节，Adapter 必须记录解释器构建、版本和实际探针清单，
不能假设跨版本兼容。参考
[CPython DTrace/SystemTap 插桩文档](https://docs.python.org/zh-cn/3.13/howto/instrumentation.html)。

### 7.5 Go Adapter

- 接入 Go 官方 mutex profile 和 block profile；
- 支持用户已有的本地 pprof 端点，或由应用显式配置的
  `SetMutexProfileFraction/SetBlockProfileRate`；
- 使用用户系统中的固定 `go tool pprof` Adapter，不在 PerfLens 内直接解析二进制 profile；
- mutex profile 在导致竞争的临界区结束/解锁调用栈上报告近似累计阻塞时间，并受事件
  采样率控制；它不是每次竞争的精确日志；
- block profile 在实际发生阻塞的位置报告累计阻塞时间，并受基于阻塞时间的采样率控制；
  它不自动提供完整 owner 关系；
- channel、WaitGroup、Cond 和 runtime 内部锁只按官方 profile 实际提供的语义报告，
  不虚构精确 owner、逐次等待或持锁区间。

规范语义以 [Go runtime](https://pkg.go.dev/runtime) 和
[Go runtime/pprof](https://pkg.go.dev/runtime/pprof) 官方文档为准；Artifact 必须保留
`SetMutexProfileFraction` 与 `SetBlockProfileRate` 的实际值，不能把两种采样机制合并。

### 7.6 外部工具、授权和项目体验

JDK、Go、async-profiler、SystemTap 等是可选外部依赖。PerfLens 自动检测版本和能力，
给出中文安装/启用说明，但不在核心两个 DEB 中隐式下载或捆绑。

所有运行时 Adapter 默认关闭。JFR、pprof 和普通启动插桩必须以目标普通用户身份运行，
不得使用 root。`LD_PRELOAD`、JVM 附加、JFR 启动、pprof 端点访问或 probe 部署都需要
独立的运行时插桩/附加授权，不能因为用户说“优化项目”就自动扩大。需要 eBPF/uprobe
特权的后端属于独立、默认关闭的管理员风险边界，不能扩大 MCP、Skill、Python Broker、
现有 stat/record Helper 或 v0.3.0 Trace Helper。计划中的项目级入口为：

```bash
perflens init --runtime-locks
```

通用 `lock` 证据先运行；只有语言识别、Adapter 能力、管理员策略和本次授权同时允许时，
Skill 才升级到运行时专用证据。

自定义锁可以通过版本化 NDJSON 导入合同接入，但这只是 Adapter 接口，不建设新的 Agent
或插件框架。每个导入流先提供严格 header，声明数据来源/版本、Adapter 版本、目标身份、
时间戳时钟和单位、`measurement_semantics`、可见锁/快路径、采样/阈值配置、丢失事件，
以及 owner/持锁时间是否真实可得；随后才允许规范化事件。未知字段、重复 header、越界
帧、非法或不匹配 PID、逆序时间、未声明语义、事件/聚合不守恒和伪造 owner 能力必须在
发布 Artifact 前拒绝。

### 7.7 v0.3.1 实施提交顺序

后续实现拆成以下独立、可回滚提交，不把四个运行时和公共 Schema 混入一个大提交：

1. 公共产物 Schema、能力发现、质量模型、NDJSON 合同和 verifier；
2. C/C++ pthread Adapter、ABI 能力检测和目标普通用户插桩；
3. Java JFR Adapter、固定配置及可选 async-profiler/JVMTI 导入接口；
4. CPython Adapter、GIL/内部锁/threading 分层和 free-threaded 能力检测；
5. Go mutex/block pprof Adapter及两类采样语义；
6. CLI、MCP、Skill 自动选择、统一报告和分页/诊断包；
7. 安全拒绝路径、插桩开销、兼容矩阵和四类真实运行时验收；
8. 中英文发布文档、两个 DEB 的升级/卸载 smoke test 和 `v0.3.1` 发布门。

## 8. 安全、性能和发布门槛

每个新增模式和 Adapter 至少需要：

- 版本化 JSON Schema、中英文语义文档、真实 fixture、Golden 和严格未知字段拒绝；
- 畸形、超限、截断、丢失、乱序、PID 复用、目标退出和工具替换测试；
- 输入/转换/Artifact 哈希绑定、区间/权重守恒、质量一致性和独立 verifier；
- 未授权 peer、跨 UID、任意路径/命令/事件、重放、过期和 spool 逃逸拒绝测试；
- 采集、插桩和解析的吞吐、p95、峰值 RSS、磁盘和目标开销预算；
- 精确事件用精确期望验收，抽样证据使用统计容差，不能混用；
- deploy、switch-mode、switch-profile、upgrade、rollback、undeploy 和包非激活测试；
- Python lint、类型、完整测试和覆盖率门禁；Rust fmt、clippy、test、audit、deny 和跨语言
  协议一致性；
- Debian 真实 systemd 主机，以及 C/C++、Java、Python、Go 真实运行时矩阵。

运行时锁矩阵必须至少覆盖无竞争、低竞争、高竞争、递归锁、读写锁、条件变量等待、目标
退出、PID 复用、符号缺失、事件丢失和 Adapter 不可用。精确后端按精确事件数/区间验收；
阈值、抽样和累计后端使用声明过的统计容差，测试不得把“没有被采样”当成“没有竞争”。
每个后端都要测量关闭、启用但空闲和高竞争三种情况下的目标开销，超过预算必须警告或
失败关闭。

需要 perf 特权时优先使用专门的 `CAP_PERFMON`；Linux 官方不建议用宽泛的
`CAP_SYS_ADMIN` 替代。任何额外 capability 必须由对应独立服务的真实拒绝日志和验收证明，
详见 [Linux perf 安全文档](https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html)。

只有分析门、安全门、兼容门和真实主机门全部通过，功能才能从“计划”改为“正式”。
优化结论仍必须区分 `observed`、`candidate`、`confirmed` 和 `Verified Improvement`；只有
正确性通过的匹配 A/B 才能称为已验证改进。

`v0.3.1` 只有在四类 Adapter、统一 verifier、安全拒绝路径、真实运行时矩阵，以及两个
DEB 的安装、升级、回滚和卸载测试全部通过后才能标记稳定。缺少任一 Adapter 时必须缩小
发布声明或推迟版本，不能仍使用“四类正式覆盖”的名称。

## 9. 发布和兼容表述

- 在 `v0.3.0` 完成前，当前发布仍只把 `stat/record` 声明为正式采集能力。
- `v0.3.0` 只在全部门禁通过后发布 `full_diagnostics` 和 Trace Helper。
- 任何一个高级模式未通过门禁时，不能用“完整诊断”名称掩盖缺失能力。
- `v0.3.1` 的四类 Adapter 必须分别列出准确支持版本、后端、采样语义和不可见快路径。
- 软件 PMU 降级继续禁止 IPC、硬件缓存和分支结论。
- PerfLens 仍不是 heap profiler、I/O APM、GPU profiler 或分布式追踪系统。
- Release Notes 必须从最终实现和测试结果生成，不能直接把本文计划当作已经完成的功能。
