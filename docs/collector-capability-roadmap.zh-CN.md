# Collector 能力评估、修复清单与扩展路线

简体中文 | [English](collector-capability-roadmap.md)

状态：适用于 PerfLens `0.2.0` 当前代码线，记录已经确认的能力边界和后续实施顺序。
本文是设计与验收计划；标为“待实施”或“候选”的内容不代表已经完成。

## 先区分两类“模式”

PerfLens 中的“模式”有两层，不能混为一谈：

- **Collector 权限模式**：`cap_perfmon` 和 `paranoid3_helper`，决定哪个进程持有何种
  Linux 权限；
- **性能采集模式**：`stat`、`record`、`sched`、`lock` 和 `off_cpu`，决定采集哪类证据。

当前产品默认只开放 `stat` 和 `record`。`cap_perfmon` 的 Python 采集路径具有另外三种
模式的固定命令构造，但它们仍属于原始证据/实验能力；`paranoid3_helper` 的独立策略上限
只允许 owner-PID 的 `stat` 和 `record`，不能通过修改 TOML 绕过。

## 总体结论

现有 Collector 已经形成了一个可用的 **CPU 性能调优最小闭环**：普通用户运行工作负载，
Broker/Helper 对明确授权的 PID 做短时 `stat` 或 `record`，MCP 分析证据，Agent 提出候选，
最后以同工作负载、同事件来源的前后测量验证。

它目前适合回答：

- 程序是否主要消耗 CPU；
- CPU 时间主要落在哪些函数和调用路径；
- 是否存在明显的上下文切换、CPU 迁移或缺页活动；
- 修改前后的热点分布和 Benchmark 是否在可比条件下改善。

它目前不能独立、可靠地回答：

- 没有硬件 PMU 时的 IPC、硬件缓存未命中率和分支未命中率；
- 精确的调度等待时长、锁等待时长和 off-CPU 阻塞时长；
- 堆分配/泄漏、磁盘与网络请求延迟、GPU、跨主机调用链或生产 APM 问题；
- 只凭一次 Profile 就确认根因或声称优化已经成功。

因此，当前状态是“CPU 调优核心可用”，不是“所有 Linux 性能问题都已覆盖”。

## 两种 Collector 权限模式

| 项目 | `cap_perfmon` | `paranoid3_helper` |
| --- | --- | --- |
| 推荐级别 | 默认、优先 | 仅在必须保留 `perf_event_paranoid=3` 时选择 |
| 公共 Broker | 专用 `perflens` 用户，持有受限 `CAP_PERFMON` | 专用 `perflens` 用户，无 capability |
| 高权限组件 | 无 root Helper | 私有 Rust Helper，以 root UID 运行，systemd 上限为 `CAP_PERFMON`、`CAP_SYS_ADMIN`、`CAP_SYS_PTRACE` |
| 普通客户端能否访问 Helper | 不适用 | 不能；Helper Socket 只允许 Broker 身份访问 |
| 支持的策略模式 | 策略模型支持五种，默认开放 `record`、`stat` | 固定只支持 `record`、`stat` |
| 目标范围 | 默认同 UID、明确 PID | 强制同 UID、明确 PID |
| Debian `paranoid=3` | 通常不可用，需要管理员另行审查内核策略 | 设计目标就是保持等级 3 不变 |
| 安全边界 | 更小，推荐 | 更大，但由双进程、私有协议、固定 capability 和独立复核收窄 |
| 适合场景 | 可以使用 `CAP_PERFMON` 的常规 Linux 主机 | 不能降低 Debian 等级 3 策略的受控单用户开发主机 |

两种模式共同遵守以下边界：

- Agent、Skill 和 MCP 都不能运行 `sudo`，也不以 root 运行；
- Collector 只接收带版本、短期、单次、绑定 PID 所有者和启动时间的类型化计划；
- Collector 不接收 shell、任意命令、任意环境、任意输出路径或 system-wide 目标；
- 项目程序由普通 MCP 用户启动，高权限组件永远不启动用户程序；
- 产物只写固定 spool，并受单文件、总字节数、文件数和磁盘保留空间限制；
- 安装、初始化和采集都不会自动修改 sysctl。

`paranoid3_helper` 的默认硬上限是单次 30 秒、99 Hz、256 MiB、计划最多 120 秒有效，
spool 最多 5 GiB/500 个产物并保留 2 GiB 文件系统空闲量。这些边界由 Python 和 Rust
分别校验。它不是“让 Agent 间接拥有 root”，而是让一个固定协议的 Helper 执行极小的
PID perf 操作集合。

### 对两种模式的评价

`cap_perfmon` 的架构更简单、权限更小，是功能和风险最平衡的长期默认方案。它的主要限制
来自 Debian 对 `perf_event_paranoid=3` 的额外收紧，而不是 PerfLens 本身缺少命令。

`paranoid3_helper` 已经证明软件 `stat` 和 `cpu-clock record` 能在等级 3 主机上完成真实
短时采集，解决了“服务健康但不能采样”的核心可用性问题。它的协议、PID 身份、重放、
spool 和部署生命周期边界比较完整；不足是权限审计成本更高、当前只覆盖 `stat/record`，
并且硬件 PMU 是否有效仍由宿主机、虚拟化平台和 CPU 暴露方式决定。

## 五种性能采集模式的成熟度

| 采集模式 | 当前证据 | 当前成熟度 | 性能调优价值 | 主要缺口 |
| --- | --- | --- | --- | --- |
| `stat` | 硬件计数器；或软件 `task-clock`、上下文切换、迁移、缺页 | 核心可用 | 判断 CPU 密集程度、调度活动；PMU 可用时支持 IPC/缓存/分支候选 | 缺少完整派生指标解释和自动匹配 A/B 编排 |
| `record` | 硬件 `cycles` 或软件 `cpu-clock` 调用栈 | 核心可用 | 找 CPU 热点、调用路径和源码位置 | 需强化 unwind 质量、未解析比例、批量源码归因和静态火焰图导出 |
| `sched` | `perf sched record` 原始证据 | 实验性 | 调查调度候选 | 尚无稳定的延迟区间解析、汇总和专用报告 |
| `lock` | `perf lock record` 原始证据 | 实验性 | 调查锁竞争候选 | 尚无稳定的等待/持锁聚合和源码归因闭环 |
| `off_cpu` | `sched:sched_switch` 栈 | 实验性 | 提供离开 CPU 的调用栈线索 | 尚未重建开始/结束区间，不能证明阻塞时长 |

“代码中能构造 perf 命令”不等于“功能已经成熟”。后三种模式在拥有确定性解析器、Golden
夹具、真实主机验收和清楚的结论边界前，不应作为默认能力宣传，更不应直接加入 Rust
Helper 的权限协议。

采集也不是固定 10 秒：策略默认只规定 **最长 30 秒**，请求可以更短；Skill 推荐初次
诊断不超过 10 秒。合理策略是先用 1～2 秒 `stat` 判断方向，再根据样本数量用 5～10 秒
`record`，而不是无条件延长采集。

## 硬件 PMU 与自动降级

项目自动采集默认使用 `event_source=auto`。在策略允许软件降级时，Collector 会先在同一
PID 和原总时长内做固定、短时的硬件探测：

1. 硬件计数有效时继续使用硬件事件；
2. 探测失败、返回不可用或没有可用计数时，`stat` 降级到固定软件事件，`record` 降级到
   `cpu-clock`；
3. Collection 产物记录 `requested_event_source`、`actual_event_source`、
   `fallback_used`、准确原因和证据限制。

软件降级后，性能调优仍可继续定位 CPU 时间、on-CPU 热点、调用路径、上下文切换、迁移
和缺页候选。它不能支持 IPC、硬件缓存未命中、分支未命中等微架构结论。A/B 两侧的
`actual_event_source` 必须相同；一侧硬件、一侧软件不属于匹配证据。

在已经验收的 Debian 13 VMware 主机上，`paranoid3_helper` 的软件计数与 `cpu-clock`
采样通过，硬件 PMU 返回无可用计数。这个结果证明自动降级路径可用，不证明所有物理机、
虚拟机或其他采集模式都可用，也不代表 root 能修复虚拟 PMU。

## 性能调优效果评估

| 问题类型 | 当前效果 | 结论边界 |
| --- | --- | --- |
| CPU 饱和、算法热点 | 好 | `stat + record + 源码` 可以形成 L2/L3 候选；仍需 A/B 才能确认改进 |
| CPU 调用路径 | 好 | 取决于调用栈、符号、Build ID 和调试信息质量 |
| IPC、缓存、分支 | PMU 可用时较好；软件降级时不足 | 只允许使用实测硬件事件，不得从源码或软件事件猜测 |
| 调度抖动、线程迁移 | 基础可用 | 软件 stat 可观察活动；精确延迟仍缺专用 sched 聚合 |
| 锁竞争 | 初步 | 原始采集入口存在，确定性等待归因尚未完成 |
| off-CPU/I/O 等待 | 初步 | 栈线索不等于等待时长，更不能自动区分磁盘、网络或锁 |
| 内存分配/泄漏 | 不足 | 当前没有 heap/allocator 专用 Adapter |
| 优化前后验证 | 部分可用 | Profile/Benchmark 比较器已有，但缺少安全的 Benchmark recipe 执行与完整工作负载身份 |

对常见的 C/C++/Rust 本地 CPU 密集程序，现有能力已经有实际价值；在硬件 PMU 正常的物理
Linux 主机上效果更完整。在 PMU 不可用的虚拟机上，它仍适合做算法级热点优化，但不适合
做缓存层次、流水线和分支预测级调优。

## 已确认修复清单

以下条目来自当前代码与文档审查。除非另有说明，它们是待实施项。

### P0：正确性、状态可信度和发布说明

1. **固定 Profile 输入身份。** 当前分析先按路径计算 SHA-256，再按同一路径重新打开解析；
   文件在两次读取之间被替换时，哈希和实际分析字节可能不一致。应通过固定文件描述符的
   单次快照/单一字节源完成哈希与解析，并在发布产物前复核设备号、inode、大小和时间身份。
2. **同步过期文档。** 兼容、限制、发布就绪和自动采集文档仍有旧 perf 版本、旧测试数量、
   “尚无真实 Collector 验收”、计划默认 5 分钟等过期描述；代码中的计划上限是 120 秒。
   “生成 FlameGraph”还应明确为生成外部渲染所需的 folded/栈证据，除非真正加入 SVG 导出。
3. **记录真实验收回执。** `perflens status` 当前是无状态检查，真实验收通过后仍只能显示
   “可进行验收”。应在普通用户 XDG 状态目录保存纯信息回执，绑定 PerfLens 版本、策略哈希/
   权限模式、perf 版本、内核 boot ID 和服务身份；任一变化后失效。该回执绝不能作为授权。
4. **增加测试覆盖余量。** 85% 门槛附近余量过小。先补 MCP Server、项目启动器、存储、
   Skill 分发、CLI 和部署拒绝路径，把常态覆盖目标提高到 87%～90%，不降低门槛。

### P1：分析和 MCP 性能

这些属于候选优化，必须先建立高基数基准，不能只凭代码外观修改：

1. 聚合器目前会完整排序所有热点和最多一百万条调用路径，Application 层之后才截取 Top-K。
   可缓存 Frame 排序键，并在严格保持确定性顺序和精确聚合语义的前提下使用有界 Top-K。
2. Profile 哈希与解析合并为固定输入快照，可同时消除一次完整文件读取。
3. MCP `ArtifactStore.save` 当前可能对同一模型序列化两次；增加“已经序列化的安全原子写”
   路径，保持不覆盖和目录同步语义。
4. MCP 分页/详情请求会反复读取并验证完整 Analysis JSON。可加入按文件身份绑定、容量有界的
   LRU 和热点索引；命中缓存前仍需复核文件身份。
5. 符号 Provider 已支持长驻批量解析，但上层单地址调用没有充分复用。增加按 Build ID/DSO
   分组的批量源码定位和有界 Provider 池。
6. 性能基准扩展到高唯一 Frame、深栈、高唯一调用路径、perf-script、MCP 冷/热缓存和符号
   冷/热解析，同时记录吞吐、p95 与峰值 RSS。

### P1：使用体验和证据完整性

1. 增加类型化 `get_collection_details` 和有界 `list_artifacts`，避免 Agent 依靠原始 JSON
   分页猜测 stat 指标或丢失旧 Collection ID。
2. `source_locations` 已按热点设置确定性上限并完成汇总；下一步把保留的调用路径继续
   汇总为同样有界的 `top_callers`、`top_callees`。
3. 为项目运行产物加入可执行文件 SHA-256/Build ID、Git 提交和受控环境指纹，使 A/B 能证明
   工作负载身份一致。
4. 为修改过的项目 Skill 提供显式“显示差异 → 备份 → 重新安装”流程；默认仍拒绝覆盖。
5. 让 `doctor/status` 分栏显示普通进程直接能力、Broker 健康、最近真实验收与其失效原因，
   并增加有界的 `diagnose-collector` 诊断包。

## Collector 扩展方案

### 阶段 C0：先稳定现有 CPU 闭环

- 保持两个权限模式和默认 `record/stat` 不变；
- 在安装包级真实环境中分别验收：`cap_perfmon` + `paranoid<=2`、
  `paranoid3_helper` + `paranoid=3`、硬件 PMU 可用、软件降级；
- 增加“项目工作负载 → record → analyze_collection → 热点/源码”的正式发布验收；
- 覆盖安装、升级、两向切换、失败回滚、卸载和历史证据保留；
- 完成上面的输入身份、状态回执、文档和覆盖率 P0 项。

这是下一阶段最值得做的工作。它不会增加权限，却能显著提高用户对结果和状态的信任。

### 阶段 C1：增强 CPU 调优质量，不扩大权限

- 只在硬件指标实测有效时计算 IPC、缓存和分支派生指标，并携带来源/不可用原因；
- 报告调用栈丢失、未解析符号比例、内核符号限制和 unwind 质量；
- 增加批量源码归因和静态 FlameGraph SVG/HTML 导出；这不是 Web UI；
- Skill 采用自适应策略：短 `stat` 分流，样本不足时在已授权上限内选择 5～10 秒
  `record`，不得自动扩大 PID、命令、时长上限或权限；
- 增加普通用户 Benchmark recipe：固定工作负载、预热、重复、正确性检查和同源 A/B。
  它不能在 Helper/root 中运行。

### 阶段 C2：先完成离线等待/竞争分析

先支持导入用户已有证据，再考虑增加采集权限：

- 为 `perf sched` 建立调度区间、运行队列延迟和线程汇总模型；
- 为 `perf lock` 建立等待次数、总等待、最大等待、持锁路径和源码归因；
- 由 sched-switch 成对事件重建 off-CPU 区间，明确丢失事件和截断区间；
- 每个 Parser 都要求流式有界、版本化 Schema、真实/合成夹具、Golden 和错误路径测试；
- 只有确定性分析成熟后，才把相应采集入口从“实验性”升级。

### 阶段 C3：可选的高权限扩展

不要简单把 `sched/lock/off_cpu` 加入 `paranoid3_helper.allowed_modes`。每增加一个模式都要：

1. 定义新的类型化协议枚举和最小字段，不提供 argv、路径、环境或 system-wide 开关；
2. 固定 perf 子命令、事件白名单和输出命名；
3. 审查 tracefs、LSM、PID 所有者和所需 capability；
4. 由 Rust 独立复核 peer、PID 身份、TTL、重放、模式、事件、时长、频率、大小和 spool；
5. 添加未知字段、跨 UID、PID 复用、重放、过期、路径逃逸、worker 失败和真实主机验收；
6. 如果所需 capability 不同，优先使用独立、按模式选择的 Helper/unit，而不是扩大现有
   Helper 的全局 capability 集；
7. 保持默认 Helper 仍只开放 `stat/record`，高级等待/竞争采集必须由管理员单独选择。

eBPF、tracefs 或更强权限不是下一步捷径。只有当确定性离线分析已经证明这些证据能回答
用户问题，并且最小权限设计经过测试时，才应引入新的 Collector 后端。

### 阶段 C4：产品和平台扩展

- 每 UID 独立 systemd 实例、Socket 和 spool，避免多用户证据泄露；
- 增加容器 PID/挂载命名空间和 DSO 路径映射，但不突破宿主授权；
- 在 Debian amd64 稳定后扩展 Ubuntu、aarch64，再评估 RPM；
- 通过 Adapter 接入 heaptrack、allocator Profile、块 I/O/网络延迟或 JIT 符号；
- 增加协议 fuzz/proptest、安装包真实 systemd VM 和硬件 PMU CI Lane。

Linux 是当前产品边界。Windows/macOS、生产常驻监控、分布式追踪、Web UI 和自动 root
诊断不应排在上述闭环之前。

## 每个阶段的验收门槛

- 结论必须携带 Collection/Analysis/Benchmark ID、事件来源和缺失证据；
- 软件降级不能生成 IPC、缓存或分支结论；事件来源不一致不能标记为匹配 A/B；
- 新协议字段有 JSON Schema、Python/Rust 共用 valid/invalid Golden 和未知字段拒绝；
- 新采集模式有未授权 peer、跨 UID、PID 复用、重放、过期、超限、spool 逃逸和失败清理测试；
- 新分析器流式、有界，不直接解析 `perf.data` 二进制；
- 改进只有在等价工作负载、正确性通过、Profile 变化对应、误差稳定且没有不可接受资源转移
  时才称为 `Verified Improvement`；
- Python lint、类型、完整测试、覆盖率、包 smoke，以及 Rust fmt/clippy/test/audit 全部通过。

## 推荐实施顺序

推荐按 **P0/C0 → C1 → C2 → C3 → C4** 推进。

最优先不是增加更多 root 能力，而是让现有 `stat/record` 从安装、状态、采集、分析、源码
归因到匹配 A/B 都稳定、可解释、可复现。完成这一步后，PerfLens 就会从“能采证据的工具”
提升为“可以持续验证 CPU 优化的产品”。等待、锁、off-CPU 和其他平台随后按独立证据模型
扩展，风险更小，也更容易判断新功能是否真正有用。
