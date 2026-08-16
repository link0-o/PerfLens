# PerfLens v0.3.0 Collector 能力扩展计划

简体中文 | [English](collector-capability-roadmap.md)

状态：**下一版本设计与验收计划**

最后审计：2026-08-15，基于 `b8b1eec` 之后的 `0.2.0` 代码线

候选目标版本：`v0.3.0`

本文严格区分“当前已经实现”和“下一版本计划”。除标记为“当前正式”的内容外，任何
路线图条目都不能写进功能宣传、安装向导的默认选项或 Skill 的自动采集承诺。

## 1. 决策摘要

建议扩大 PerfLens 对调度、锁和 off-CPU 问题的分析边界，但按以下顺序推进：

1. **先扩确定性离线分析，再扩实时采集权限。** 先分析用户已有或管理员导出的证据，证明
   数据模型和结论确实有用。
2. **`stat` 和 `record` 继续是唯一默认正式采集模式。** 当前 CPU 调优闭环已经有实际价值，
   不应为了增加模式数量破坏稳定性。
3. **`cap_perfmon` 只在专用分析器、隐私检查和真实主机验收全部通过后，实验性开放单个
   高级模式。** 不能一次性打开 `sched`、`lock`、`off_cpu`。
4. **`paranoid3_helper` 在 `v0.3.0` 继续硬限制为 `stat/record`。** 不向现有 Rust 协议枚举、
   Helper Socket 或 systemd capability 集加入 trace 模式。
5. **如果以后必须支持 `paranoid=3` trace 采集，另建可选 Trace Helper。** 它必须拥有独立
   unit、Socket、协议、策略、私有原始 spool、风险确认和卸载流程。

因此，`v0.3.0` 的推荐产品定位是：

> 保持可靠的 CPU 调优核心；新增有证据质量门禁的等待/调度离线分析；只把通过安全验收的
> `cap_perfmon` trace 采集作为默认关闭的实验能力，不扩大 paranoid=3 的 root 边界。

## 2. 两类模式不能混淆

- **Collector 权限模式**：`cap_perfmon`、`paranoid3_helper`；决定哪个系统进程持有什么权限。
- **性能采集模式**：`stat`、`record`、`sched`、`lock`、`off_cpu`；决定采集哪类证据。

权限模式和采集模式不是一一对应。策略或 Schema 中出现某个采集模式，也不代表该权限模式
已经安全支持它，更不代表 PerfLens 已经能稳定解释其结果。

本文使用四个成熟度标签：

- **当前正式**：默认产品路径、具有确定性分析和发布验收；
- **当前实验入口**：代码能生成固定命令或保存原始产物，但没有完整专用分析闭环；
- **v0.3.0 计划**：只有实现和验收完成后才能对用户开放；
- **明确不支持**：本版本不应执行或宣传。

## 3. 当前 `0.2.0` 事实基线

### 3.1 代码和策略实际状态

| 层 | `stat` / `record` | `sched` / `lock` / `off_cpu` |
|---|---|---|
| 公共 Python 类型与 Schema | 已表达 | 已表达 |
| MCP/CLI 参数 | 已暴露 | 已暴露，但不等于正式支持 |
| 项目初始化默认自动模式 | 默认启用 | 默认不启用 |
| Broker 默认策略 | `record, stat` | 默认拒绝 |
| `cap_perfmon` Python Collector | 固定 argv、产物和边界 | 有固定原始采集命令入口 |
| `paranoid3_helper` Python 策略 | 允许 | 硬拒绝其他模式 |
| Rust Helper 私有协议 | 仅 `Record`、`Stat` | 枚举不存在，严格拒绝 |
| Agent 可用的确定性分析 | stat 类型化指标；record 热点、调用路径、源码和证据校验 | 只有通用 perf.data 路径，没有专用延迟/等待 Artifact |
| 当前成熟度 | **当前正式** | **当前实验入口** |

当前 `cap_perfmon` 路径固定构造：

- `perf sched record`；
- `perf lock record`；
- `perf record -e sched:sched_switch` 形式的 off-CPU 栈证据。

这些入口仍缺少稳定的配对区间、延迟分布、锁 owner/waiter、丢失事件解释和专用结论门禁。
把普通 `perf script` 热点分析套在 trace 产物上，不能替代这些分析器。

### 3.2 当前 CPU 调优闭环

当前正式闭环为：

```text
精确工作负载授权
        ↓
短时 stat（硬件或软件事件）
        ↓
需要调用栈时 record（cycles 或 cpu-clock）
        ↓
原始证据哈希、事件和来源绑定
        ↓
热点、调用路径、源码和 EvidenceQuality
        ↓
正确性测试 + 同工作负载、同事件来源 A/B
```

`b8b1eec` 已完成的关键基础不再列为待修复：

- stat 原始 CSV 哈希与类型化指标精确回放；
- record Collection、事件来源、转换文本和 Analysis 身份绑定；
- 未知调用栈位置保留为 unknown Frame，避免错误 Self 归因；
- Agent 可见内容摘要、分析指纹、权重守恒和独立 `verify_analysis`；
- Python/JIT、C/C++、Rust、Go、Java 样式符号回归矩阵；
- MCP 分页和详情加载时重新校验对象身份；
- 项目工作负载就绪握手、进程组清理和 CI 超时稳定性；
- 硬件正式采集无可用计数时，在原授权窗口内安全降级。

仍然缺少的是更高层的工作负载身份、稳定 Benchmark 编排、等待/竞争分析器和更宽真实主机
矩阵，而不是原始证据到 Agent 的基本完整性门禁。

## 4. 当前能力够不够做性能调优

| 性能问题 | 当前效果 | 能否做较好调优 | 证据边界 |
|---|---|---|---|
| CPU 饱和、算法复杂度 | 好 | 可以 | 仍需正确性和匹配 A/B 才能称为改进 |
| 函数热点、调用路径 | 好 | 可以 | 取决于 unwind、符号、Build ID 和调试信息 |
| C/C++/Rust/Go CPU 热点 | 好 | 可以 | 缺调试信息时只能到符号级 |
| Python/JIT CPU 热点 | 中到好 | 可以 | 依赖运行时 perf map/sidecar；跨时间回放可能受限 |
| IPC、缓存、分支预测 | 条件性 | PMU 可用时可以 | 软件降级时明确不支持这些结论 |
| 修改前后 CPU 验证 | 基本可用 | 可以 | 必须同工作负载、同事件来源并包含正确性测试 |
| 调度延迟、线程长期 runnable | 不完整 | 目前不够 | stat 活动计数不能给出延迟区间或分位数 |
| 锁竞争、owner/waiter | 不完整 | 目前不够 | on-CPU futex/mutex 栈不能证明等待时长 |
| CPU 不高但墙钟时间长 | 不完整 | 目前不够 | 缺少配对 off-CPU/唤醒/重新运行区间 |
| 内存分配、泄漏、碎片 | 不支持 | 不够 | 需要独立 allocator/heap Adapter |
| 磁盘、网络请求延迟 | 不支持 | 不够 | 需要设备/系统调用/请求级关联证据 |
| GPU、跨主机追踪、生产 APM | 不在边界 | 不够 | 不是下一版本目标 |

结论：当前能力足以对 CPU 密集型程序做有价值且可以验证的算法级、函数级调优；硬件 PMU
可用时还能提供微架构候选。在当前 VMware 软件降级环境中，仍能定位 on-CPU 热点和调用
路径，但不能推断 IPC、缓存或分支。对于“程序很慢但 CPU 不高”的问题，必须扩大等待和
调度证据，不能继续依赖 on-CPU Profile 猜测。

较少的 context-switch、migration 或 page-fault 只代表本次观察到这些事件较少，不能证明
不存在 I/O 等待、锁竞争、分配抖动或内存压力。

## 5. `v0.3.0` 发布范围

### 5.1 必须交付

1. 当前 `stat/record` 闭环保持兼容，现有 `0.2.0` Collector 策略和证据可继续使用。
2. 新增版本化、流式、有界的调度与等待证据公共模型。
3. 完成导入型 `sched` 与 `off_cpu` 确定性分析；`lock` 至少完成公共模型、转换契约和
   Golden，只有聚合语义稳定后才标记 beta。
4. 每种分析都返回独立 EvidenceQuality、允许/禁止结论、丢失/未配对/截断统计。
5. Skill 能根据问题选择现有正式证据；高级模式不可用时明确报告缺口，不得假装已经采集。
6. 文档、CLI 帮助、MCP 描述和状态输出使用同一成熟度术语。

### 5.2 条件性交付

只有全部安全门通过，才在 `cap_perfmon` 中加入默认关闭的实验性 `sched` 或 `off_cpu`
实时采集。`lock` 采集不因已有命令包装器而自动晋级。

### 5.3 明确不进入 `v0.3.0`

- 不扩大现有 Rust Helper 的 `Record/Stat` 枚举；
- 不给 Agent、Skill 或 MCP root、sudo 或 capability；
- 不允许 `perf -a`、任意 tracepoint、任意 perf 参数或任意输出路径；
- 不自动修改 `perf_event_paranoid`、tracefs、sysctl、capability 或 LSM；
- 不承诺生产常驻监控、Web UI、Windows/macOS、GPU、分布式追踪；
- 不把 eBPF 作为绕过证据模型和权限审查的捷径；
- 不直接解析 `perf.data` 二进制。

## 6. 数据模型与确定性分析设计

### 6.1 共同来源模型

三类高级分析必须共享以下来源字段：

- `schema_version`、artifact ID、输入 SHA-256/大小；
- 固定外部转换器的规范路径、版本、SHA-256、精确 argv 和 locale；
- 目标 PID/TID、UID、启动时间和采集时间范围（可用时）；
- 时间戳时钟/单位、CPU、事件类型、原始事件数；
- 丢失事件、乱序、重复、未配对、未知任务状态、解析警告和截断数量；
- 是否观察到目标外任务元数据，以及该数据是否被拒绝或隔离；
- `quality_status`、`allowed_conclusions`、`forbidden_conclusions`、`limitations`；
- 内容摘要和转换指纹，支持独立验证和不可变分页。

系统 `perf` 负责把 `perf.data` 转换为固定文本字段。PerfLens 解析转换结果，不实现自己的
二进制 perf.data 解码器。

### 6.2 SchedulerAnalysisArtifact

至少包含：

- 每个 PID/TID 的 on-CPU 区间与总运行时间；
- wakeup 到 switch-in 的 runnable/run-queue 延迟；
- switch-in、switch-out、wakeup、migration 和上下文切换次数；
- 平均值、p50、p95、p99、最大值以及分位数样本数；
- 最严重延迟区间对应的线程、CPU 和有界调用路径；
- preempted/runnable 与 sleeping/blocked 状态的明确区分；
- 开头/结尾被截断、PID/TID 复用、缺失 wakeup 或 switch 事件的数量。

没有完整 wakeup 与 switch-in 配对时，不能输出伪造的 runnable 延迟。低事件数分位数必须
标为不稳定，不能只展示 p99 而隐藏样本数量。

### 6.3 OffCpuAnalysisArtifact

每个完整区间至少记录：

```text
switch-out
    ↓ blocked/sleeping interval（仅在任务状态和 wakeup 完整时）
wakeup
    ↓ runnable delay
switch-in
```

字段包括 PID/TID、开始/结束时间、总 off-CPU 时长、可分离时的 blocked 时长和 runnable
时长、切出调用栈、唤醒者、任务状态、CPU 迁移以及完整性状态。

“磁盘”“网络”“锁”“定时器”等等待类别只能是带证据说明的候选。仅凭函数名、线程名或
任务状态不能确认等待机制。

### 6.4 LockAnalysisArtifact

在底层 perf 输出确实提供相应字段时，聚合：

- 竞争次数、成功/失败/未知事件数；
- 总等待、平均、p50/p95/p99、最大等待；
- owner/waiter 关系和锁地址的稳定匿名 ID；
- 等待方和获取方调用路径、源码归因；
- 持锁时间只在 acquire/release 能可靠配对时输出；
- 递归锁、读写锁、事件丢失和地址复用限制。

如果所用 perf/kernel 只能提供 contention 而不能可靠提供持锁区间，字段必须为 unavailable，
不能用等待时间代替持锁时间。

## 7. 实施里程碑

### M0：冻结当前 CPU 核心基线

- 保留 `stat/record` 默认策略、协议和产物兼容；
- 把已完成的证据完整性修复从路线图待办移到 CHANGELOG；
- 修复过期 TTL、旧 perf/内核版本、旧覆盖率和“所有五种模式已支持”的文档；
- 为当前 Python 软件降级验收保留环境与限制说明，但不把单机结果泛化。

验收：文档一致性检查、现有全套 Python/Rust/DEB 门禁不回退。

### M1：转换契约和公共 Schema

- 先固定每种 `perf script`/`perf sched`/`perf lock` 外部转换命令和允许字段；
- 建立共同事件 IR 和三个版本化 Artifact；
- 拒绝未知字段、非有限时间戳、负时长、逆序区间和超限基数；
- 添加真实格式 fixture、合成边界 fixture、Golden 和 Schema 生成检查；
- 所有诊断和原始预览有界。

验收：同一冻结输入重复转换字节一致；错误行隔离但损失可见；权重/区间守恒失败关闭。

### M2：`sched` 离线分析

- 重建 switch-in/out 和 wakeup 配对；
- 输出每线程运行与 runnable 延迟分布；
- 处理迁移、抢占、trace 起止截断、PID/TID 复用和 lost events；
- 提供 CLI/MCP 的分析、详情、分页、验证和诊断包接口。

验收：至少覆盖单线程、多线程、迁移、抢占、缺失 wakeup、乱序、丢失事件和超限输入；
没有完整配对时返回 `partial`，不输出伪精确延迟。

### M3：`off_cpu` 离线分析

- 在 M2 的统一调度 IR 上重建 off-CPU 区间；
- 分离可证明的 sleeping/blocked 与 runnable 等待；
- 聚合切出路径、唤醒者和任务状态；
- 明确禁止从路径名称确认 I/O 或锁根因。

验收：区间总量守恒；开头/结尾截断和未配对事件单独计数；跨任务数据不会通过详情或分页
越界泄露。

### M4：`lock` 离线分析

- 固定支持的 perf 版本输出契约；
- 建立 contention、等待分布、owner/waiter 和可选持锁区间；
- 与 sched/off-CPU 证据通过 Artifact ID 关联，而不是把不同语义混成一个百分比；
- 增加并发正确性、压力和 race 测试要求。

验收：等待与持锁语义不能混用；丢失事件导致 `partial`；没有 owner 证据时不得猜 owner。

### M5：`cap_perfmon` 实验采集评估

先进行真实主机只读研究，再决定是否开放。必须证明：

1. `-p <目标>` 和固定事件不会把其他 UID 的原始任务数据发布到组可读 spool；
2. tracefs、perf_event_paranoid、LSM、内核和 perf 版本组合的最小权限已明确；
3. `CAP_PERFMON` 足够时不增加 `CAP_SYS_ADMIN`；不足时本版本失败关闭，不偷偷扩大 unit；
4. 采集仍绑定同 UID PID 和启动时间，不支持 system-wide；
5. 原始产物在发布前经过目标范围、大小、事件和隐私检查；
6. 事件丢失超过门槛时结果为 `partial` 或失败，不能标为完整。

若通过，引入 policy v2 的显式实验段；旧 policy v1 继续支持 `stat/record`，升级不得自动迁移：

```toml
[collector]
policy_version = 2
allowed_modes = ["record", "stat"]

[collector.experimental_trace]
enabled = false
allowed_modes = []
max_duration_seconds = 10
max_output_bytes = 67108864
allow_other_task_metadata = false
```

具体字段以实现后的 Schema 为准；这里是设计目标，不是当前可用配置。管理员必须生成候选、
审查 diff、运行 `--dry-run` 后显式启用。默认仍为空列表。

### M6：Skill 证据路由和验证闭环

默认自动策略：

```text
1～2 秒 stat
   ├─ CPU 密集且需要栈 → 5～10 秒 record
   ├─ runnable/迁移候选 → sched（仅在已启用实验策略内）
   ├─ 明确锁等待问题 → lock（仅在专用分析器稳定后）
   └─ CPU 不高、墙钟长 → off_cpu（仅在已启用实验策略内）
```

Skill 只能在用户已批准的精确工作负载和管理员策略范围内选择证据。它不能自动增加 PID、
命令、时长、事件、权限或采集模式；高级模式不可用时应报告缺失证据和导入方法。

优化仍需同工作负载、同环境、同实际事件来源、正确性测试和匹配 A/B。调度/锁证据改善
不能自动等价为端到端延迟改善。

### M7：发布候选与降级

- `v0.3.0` 升级保留现有 policy、spool 和服务模式；
- 新实验策略默认关闭，可以原子回滚到原 policy；
- 新 Artifact 是新增 Schema，不原地改写旧 Analysis；
- `paranoid3_helper` 升级前后协议仍只接受 `record/stat`；
- 安装包不启用服务、不选择高级模式、不修改 sysctl；
- 任何高级模式门禁未通过时，从发布范围删除该模式的实时采集，不延迟核心 CPU 修复发布。

## 8. 为什么暂不扩大 `paranoid3_helper`

当前 Helper 已在 root UID 和 `CAP_PERFMON`、`CAP_SYS_ADMIN`、`CAP_SYS_PTRACE` 的严格 systemd
上限内运行。虽然协议很小，但 trace 模式会增加以下风险：

- sched/lock 事件天然涉及目标以外的调度者、唤醒者或锁参与者；
- tracepoint/tracefs 和不同内核、LSM、perf 版本的权限行为差异更大；
- 原始证据可能暴露其他任务名称、PID、调用栈或内核地址；
- 新 perf 子命令拥有不同 argv、生命周期和失败清理语义；
- 当前 Rust 协议、Golden 和重放标记只证明 `stat/record` 边界。

把三个字符串加入 allowlist 会绕过独立协议设计和审计，不可接受。

未来 Trace Helper 至少需要：

- 独立 systemd unit、服务用户、私有 Socket 和私有原始 spool；
- 独立 Rust 协议和 capability 审计；
- 只向 Broker 发布经过目标过滤和脱敏的派生产物；
- 单独管理员风险确认、部署、升级、回滚和卸载命令；
- cross-UID、其他任务元数据、PID 复用、重放、过期、超限、spool 逃逸和 worker 失败测试。

这属于 `v0.4.0+` 候选，不是 `v0.3.0` 承诺。

## 9. 性能与资源预算

新解析器必须：

- 按事件流处理，不把完整 trace 一次性载入内存；
- 继续服从输入字节、行长、逻辑事件、唯一任务、唯一锁、调用路径和输出页上限；
- 对分位数算法说明是精确、有界近似还是因上限不可用；
- 在高事件率、深栈、高 TID/锁基数、丢失/乱序输入上记录吞吐、p95 和峰值 RSS；
- MCP 只返回有界页，完整原始数据保留为不可变 Artifact；
- 不为通过 fixture 特判符号、PID、锁地址或事件顺序。

具体数值预算必须由可重现基准确定后写入 `performance-budget`，不能先凭感觉宣称性能足够。

## 10. 安全与质量发布门槛

每个新模式至少需要：

- 版本化 JSON Schema 和中英文语义文档；
- 真实格式 fixture、Golden、畸形/超限/截断/丢失事件测试；
- 输入、转换、Artifact 内容摘要和独立 verifier；
- 未授权 peer、跨 UID、PID 复用、重放、过期、未知字段、任意路径/命令/事件拒绝测试；
- spool 配额、失败清理、服务升级/回滚/卸载和包非激活测试；
- Debian 真实 systemd 主机验收，并记录 kernel、perf、tracefs、LSM 和 capability；
- Python lint、类型、完整测试和覆盖率门禁；
- Rust 变更时的 fmt、clippy、test、audit、deny 和跨语言协议一致性；
- 文档明确区分 `observed`、`candidate`、`confirmed` 和 `Verified Improvement`。

只有分析器门禁通过，才能进入采集安全门；只有安全门和真实主机门通过，才能把某个高级
模式从“原始实验入口”改为“实验支持”。默认正式支持需要至少一个版本周期的真实反馈。

## 11. 推荐实施顺序

```text
M0 文档与 CPU 基线
  → M1 共同转换/Schema
  → M2 sched 离线分析
  → M3 off_cpu 离线分析
  → M4 lock 离线分析
  → M5 cap_perfmon 单模式实验采集
  → M6 Skill 路由与 A/B
  → M7 发布、升级和回滚验收
```

不应并行扩大 Helper 权限和发明三个分析器。先把证据语义做对，才能判断额外权限是否值得。

## 12. 发布时对用户的准确表述

`v0.3.0` 在所有门禁完成前，只能承诺：

- `stat/record` 是正式 CPU 调优能力；
- `sched/off_cpu` 导入分析是计划中的 beta，完成后按实际发布说明列出；
- `lock` 的成熟度以最终验收为准；
- `cap_perfmon` 高级采集默认关闭且可能从发布范围移除；
- `paranoid3_helper` 仍只支持 `stat/record`；
- 软件 PMU 降级不会产生 IPC、缓存或分支结论；
- PerfLens 不是 heap profiler、I/O APM、GPU profiler 或分布式追踪系统。

最终 Release Notes 必须从实际实现和测试结果生成，不能直接复制本文的计划条目。
