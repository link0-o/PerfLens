# PerfLens 已知问题

简体中文 | [English](known-issues.md)

本文记录已经复现、具有明确边界和临时处理方法的问题，包括已经修复的问题。
不要通过降低部署器安全检查来规避问题；升级前仍可按对应版本的临时方法处理。

## KI-2026-08-26：自动 PMU 探测可能提前放行快速 Docker workload（已修复）

- 影响范围：托管 Docker `stat`/`record` 使用 `event_source=auto`，尤其是优化候选明显快于
  baseline 的 A/B；
- 现象：较慢 baseline 可以成功采集，而较快 candidate 会在正式 profile 的事件禁用绑定握手
  处重复失败。失败调用仍会消耗 workload run 预算，因为 lease 在启动容器前已经预留；
- 根因：短时硬件可用性 probe 与正式 profile 共用了 Gate-ready 回调，导致 PID 1 在 probe
  阶段就被放行。慢 baseline 尚未结束时正式软件降级还能附加；快速 candidate 则可能先退出；
- 修复：两种 Collector 实现都在整个 PMU probe 期间保持 package Gate 阻塞，只有最终选中的
  正式硬件/软件 profile 可以报告就绪。由于阻塞中的 Gate 合法地没有用户工作，即使 perf
  报告了调度运行时间，零计数也不能证明虚拟 PMU 会为真实负载产生有用证据；`auto` 因此保守
  降级，需要硬件证据时仍可显式使用 `hardware_required`；
- 失败语义：workload lease 签发后的 optimization 采集失败会精确计费一次、退还未使用的
  时间/证据预留，并阻止该 Session 后续 build/collection；lease 签发前的校验拒绝不计费，
  但仍不能原样重复。两者都不得占用 build/test 重试，也不得换模式继续尝试。
  如果 candidate 已存在但尚未生成 A/B Iteration，typed finalizer 会记录 `not_evaluated` 的
  保留/恢复 Disposition，而不会把 Build ID 当成 Iteration ID；
- 回归覆盖：Python/Rust 均证明 probe 不发送 ready、已调度的零计数仍不足以证明可用、正式
  profile 只放行 Gate 一次；同时覆盖失败计费、拒绝原样重试，以及未评估 candidate 只有在
  新鲜明确同意后才能保留。

## KI-2026-08-26：控制命令修复后 perf 就绪仍可能偶发失败（已修复）

- 影响范围：两种 Collector 权限模式下的 PID `stat`、`record` 就绪链路。Rust Helper 原来
  只用一次固定 5 秒 ACK 读取；Python `cap_perfmon` Runner 则会先等待控制回调，再排空 perf
  的有界诊断输出；
- 现象：Docker optimization 正常完成 baseline 构建后，可能在 Gate 放行前以事件禁用绑定
  握手错误失败；不改变负载直接重新运行又可能成功。失败尝试不会放行 workload，也不会
  发布 Collection 证据；
- 根因：慢但仍存活的 perf 启动与子进程提前退出、控制通道关闭或 ACK 非法没有分开；Python
  路径还可能让较多 stderr 填满管道，反压仍在等待控制命令的 perf。最后，
  `event_source=auto` 可能把通用控制故障当成 PMU 执行失败并尝试软件降级，从而掩盖基础设施
  故障；
- 修复：Python 与 Rust 的 `disable → 身份复核 → enable` 共用一个 8 秒、感知子进程存活
  状态的启动截止时间；Python Runner 在控制回调等待期间持续排空有界 stdout/stderr。存活
  但超期返回 `EXTERNAL_TOOL_TIMEOUT`；提前退出、通道关闭、ACK 非法继续返回彼此可区分的
  `EXTERNAL_TOOL_FAILED`，阶段统一为 `perf_control`。控制阶段故障绝不会被改写成 PMU 降级，
  也绝不会放行 workload Gate；之后若有界停止阶段的控制命令失败，也保留同一阶段且不能
  触发软件重采；
- 回归覆盖：超过旧 5 秒猜测但仍存活的启动可以成功；诊断管道压力不会锁死就绪；两段控制
  命令不能各自重新获得一份超时；子进程/控制通道故障只尝试一次，不发送就绪回执，也不
  软件降级。

该修复没有增加自动重试。真实控制故障仍会消耗已授权的尝试，在 workload 放行前停止，并
精确报告失败阶段。应部署相互匹配的主包与 Collector 包、重启服务，再执行一次新的显式
授权验收。

## KI-2026-08-26：不受支持的 perf control ping 阻断 PID 采集（已修复）

- 影响范围：当已安装 perf 不实现未公开的 `ping` 控制命令时，经 Python `cap_perfmon`
  Collector 或高权限 Rust Helper 执行的 PID `stat`、`record` 采集；
- 现象：Docker optimization 可以完成 baseline 构建，但第一次采集会在 Gate 放行负载前
  失败；高权限路径返回
  `Privileged perf did not complete its disabled-event binding handshake`，且不发布 Collection
  证据；
- 根因：当前 perf 对 `stat --control` 和 `record --control` 都公开支持 `enable`、`disable`，
  PerfLens 却把 `ping` 当作初始非启用屏障；测试替身也错误接受该命令，因而没有暴露真实
  工具兼容性问题；
- 修复：perf 仍以 `-D -1` 让事件保持禁用，PerfLens 随后发送幂等 `disable` 并要求有界 ACK；
  只有屏障完成后才重新核验 PID/UID/启动时间和容器身份，再发送 `enable` 并放行负载。
  ACK 非法、超时、身份变化和额外帧仍会安全拒绝；
- 回归覆盖：Python 与 Rust 测试替身现在只接受公开的 `disable → enable` 顺序，同时覆盖
  Linux perf 的 NUL 分隔 ACK 帧，以及身份变化必须在 enable 前拒绝。

这是 perf 控制命令兼容性缺陷，不是 Docker 授权、镜像、Benchmark、
`perf_event_paranoid` 或 PMU 降级故障。应安装相互匹配的修复后主包与 Collector 包并重启
托管服务，不要绕过 Broker 或降低主机安全策略。

## KI-2026-08-26：`local_only` 未拒绝所有逐条 `RUN` 网络覆盖（已解决）

- 影响范围：v0.3.2 Docker 优化使用 `network_tier = "local_only"` 或 `pinned_pull`，且
  Dockerfile 显式包含 `RUN --network=default` 或其他非 `none` 的逐条网络值；
- 预期边界：允许的 pinned pull 完成后，实际构建本身不得联网；
- 修复：Dockerfile 校验会拒绝格式错误和未知的逐条网络覆盖；`local_only`、`pinned_pull`
  只允许 `RUN --network=none`，管理员固定联网层只允许 `none` 或 `default`。外层 Buildx
  网络仍独立从已授权层级派生；
- 回归覆盖：包含离线层对 `default`、`host`、自定义值的拒绝，以及 pinned offline 与管理员
  联网层的正常路径。

## KI-2026-08-26：Claude Code 与 Copilot 不能在一次初始化中原子共同选择（已解决）

- 范围：一次 `perflens init` 或用户默认集合同时包含 `claude-code` 与 `copilot`；
- 原因：Claude Code 与 Copilot CLI 都使用项目 `.mcp.json`，旧引导却从同一个更新前身份
  分别生成两个修改计划；
- 修复：引导要求生成内容和已记录所有权副本一致，只创建并应用一次原子共享计划，同时记录
  两个客户端。detach 会在任一客户端仍保留时保留共享条目，并在二者都移除时只删除一次。

## KI-2026-08-26：组写校验假定同数字组是私有组（已解决）

- 范围：v0.3.2 构建上下文中文件或目录可被组写，且其数字 GID 恰好等于调用用户数字 UID；
- 修复：数字 UID/GID 相等不再构成信任。组可写条目只有在账户与组数据库能够证明它是调用
  用户的主组、没有其他账户把它作为主组、且没有列出不同附加成员时才会接受；身份缺失或
  有歧义时安全拒绝，其他用户可写仍永久禁止。

## KI-2026-08-26：过期优化状态不会同步回收（已解决）

- 修复：生产运行时会注册有界到期定时器，后续任意运行时交互也会清理过期状态；MCP 连接
  关闭时撤销活动授权并释放私有 Buildx 状态、快照及身份已核验的临时镜像。显式撤销仍可
  幂等执行。进程崩溃仍可能留下已证明归属的对象供人工审查；禁止全局 Docker prune。

## KI-2026-08-26：生成的优化模板夸大了编辑强制能力（已解决）

- 范围：`perflens init --docker` 生成的 schema 1.1 `[optimization]` 注释；
- 修复：生成的中英文模板改为“只有 `mutable_paths` 的变化能进入候选构建快照”，同时明确
  实际编辑/写入权限由客户端沙箱负责，并继续禁止会话授予 commit、push、Tag 或 Release。

## KI-2026-08-15：高级 trace 原始入口容易被误认为稳定分析能力（已解决）

- 范围：公共模式类型与 `cap_perfmon` Python Broker 可以构造 `sched`、`lock`、`off_cpu`
  原始 perf 证据，旧文档曾把五种模式并列描述；
- 历史边界：生成策略只启用 `record`、`stat`，`paranoid3_helper` 会拒绝另外三种模式，
  当时也没有类型化的调度延迟、锁或配对 off-CPU 产物；
- 风险：开放原始模式可能带出非目标任务元数据，产生依赖内核/perf 版本的证据，或者让
  Agent 对尚未重建的等待时长作出过强结论；
- 解决：v0.3.0 增加独立 Trace Helper、目标过滤、确定性的 `sched/off_cpu/lock` 证据与分析、
  验证产物和显式 `full_diagnostics` 配置。现有高权限 stat/record Helper 仍只允许
  `record/stat`。丢失、截断、边界缺失或无法配对的 trace 证据仍必须报告 `partial`；futex
  证据仍不能凭空生成用户态锁 owner 或持锁时间。详细边界见
  [《采集能力扩展路线图》](collector-capability-roadmap.zh-CN.md)。

## KI-2026-08-15：原始 perf 证据到 Agent 投影缺少端到端复核（已修复）

- 风险：原始文件的 SHA-256 正确，并不自动证明后续类型化指标、热点、调用路径和 Diagnosis
  一定仍与它一致。审查还发现两个具体失真路径：无法解析的调用栈行被丢弃时，父帧可能被
  错记为 Self 热点；硬件探测成功但正式硬件 stat 只返回零计数时，失败产物曾先占用正式
  路径，使 `auto` 软件回退无法恢复。
- 修复：Collection 使用同一个禁止跟随符号链接的描述符快照重新校验文件身份、大小和摘要；
  stat 原始 CSV 会被独立重放，必须逐项得到保存的类型化指标。Analysis 绑定转换清单、来源
  Collection、完整 Agent 可见内容与全部派生守恒关系；record 事件也必须与转换文本一致。
  混合架构 PMU 的固定 `cpu_core/`、`cpu_atom/` 事件展开会在核对时安全规范化，同时保留
  原始指标身份。
  无法解析的调用栈位置保留为有界 `unknown` Frame。正式硬件结果先在临时文件中验证，只有
  合格结果才能发布；`auto` 才能在剩余授权时长内安全转为软件事件。
- Agent 门禁：MCP 加载和分页 Analysis、Collection、Diagnosis 时都执行对应类型校验。
  Diagnosis 绑定来源 Analysis 内容摘要并可重复安全读取；A/B 比较拒绝不同事件来源、权重
  语义或转换器身份被当作 matched evidence。
- 通用边界：这些检查位于共享 CSV、perf-script、聚合和 Artifact 层，不是 Python 专用
  修补。C/C++、Rust、Go、CPython 和 Java/JIT 都经过同一门禁；语言只影响外部符号质量。
  回归 fixture 覆盖常见格式，但不等于对所有编译器、JDK 或 perf 版本的实机认证。
- 剩余限制：摘要不是抵抗恶意文件所有者的数字签名，也不能证明内核 PMU 或 perf 本身绝对
  正确。PerfLens 仍不直接解析 perf.data；未冻结的 JIT/Build-ID sidecar 不能承诺跨主机、
  跨时间完全重放。遇到未知格式会降为 `partial` 并禁止超出证据的结论。

## KI-2026-08-14：Frame/注释误判、Python perf-map 与重复公开调用路径（已修复）

- 现象：有效的 CPython `-X perf` 证据虽然全部样本都能解析，但会针对
  `python3.13[offset]`、`[JIT] tid N[offset]` 产生数百条
  `Callchain frame has no hexadecimal IP`；由于精确 IP 不同，公开结果还可能出现大量
  符号和 DSO 完全相同的重复调用路径；
- 根因：启用 `srcline` 后，这两种方括号行和独立的 `文件:行号 (inlined)` 行是 perf 对
  上一帧输出的注释，并不是 Frame；内部调用路径使用精确 Frame 身份，而公开契约只显示
  `(symbol, DSO)`。早期修复先判断“像源码注释”，再判断完整 Frame，导致“无源码叶帧后
  紧跟有源码父帧”这种合法 native 栈也可能把父帧吞掉；
- 修复：只有偏移与上一帧相同、标签又匹配该 DSO 或 JIT 线程的行才会作为重复注释忽略；
  严格的独立源码注释只补充紧邻的上一帧。解析器同时识别 CPython 官方的
  `py::函数:文件名` perf-map 格式。公开路径按显示的 `(symbol, DSO)` 序列聚合，源码位置
  以固定上限汇总到热点，只有真实行号才会设置 `has_source_lines=true`。完整十六进制 IP
  Frame 现在始终先解析，再考虑严格注释；
- 通用性验证：Golden 同时覆盖 C/C++ 模板/内联/带括号 DSO、Rust hash 合并、Go 方法、
  Java/JIT perf-map、Python perf-map 和普通 native 父子帧。对 `perf.data`，Java/JIT 没有
  冻结转换文本或 sidecar 时仍明确禁止跨时间符号重放；不把 fixture 通过夸大成所有 JVM
  版本均已实机验收；
- 报告边界：PerfLens 调用路径顺序固定为“根/调用者 → 叶子/被调用者”。缺失 DWARF 行号
  和未解析的原生帧仍会如实保留；修复不会凭空补出 perf 没有记录的 Python 深层栈。
- 实际证据复验：对最初报告问题的 CPython `perf.data`（272 个样本）重新转换后，591 条
  Frame 全部进入聚合，589 条地址注释和 2 条源码注释被单独计数，malformed 为 0；原来
  数百条“没有十六进制 IP”警告消失，只保留 1 条确实缺少 DSO 的 native Frame 警告。
  `cpu-clock` 总权重现在明确标为纳秒，独立验证的内容/指纹/权重守恒/原始 SHA 均通过；
  因 JIT sidecar 未冻结和 5.88% 未解析 Self，质量仍诚实保持 `partial`。

同一轮还收紧了 stat 报告口径：`running_percent` 是 perf 事件调度覆盖率，不是进程 CPU
利用率；较低的上下文切换、迁移或缺页计数不能证明不存在 I/O 等待、锁竞争、频繁分配
或内存压力。采样 Profile 的 `perf period` 也不再统一标成 `event_count`：
`cpu-clock`/`task-clock` 明确为纳秒，cycles/instructions 使用对应单位，陌生事件才保留
通用计数单位，避免 Agent 把正确数值配上错误物理单位。

`perf stat` CSV 解析也不再用替换模式吞掉非法 UTF-8：非法字节会让该证据失败关闭，避免
事件名被静默改变；错误的 CSV 行会产生有界警告而不破坏后续合法指标，警告超限则明确
标记为已截断。该修复与被测语言无关。

源码位置现在只在有效样本进入聚合时收集；被栈深等规则排除的坏记录不会再给同名有效热点
附加错误位置。每个热点的位置列表保持固定上限，发生截断时会在 Hotspot 和
EvidenceQuality 中同时暴露，Agent 不得宣称位置列表完整。

同一修复还解决了专用 Helper UID 产物无法分析的问题：普通授权用户虽然能读取
`/var/lib/perflens-helper` 中的证据，`perf script` 仍会额外拒绝非当前用户/root 所有的
文件。适配器现在只对已经通过路径、大小和 SHA-256 校验的输入固定追加 `--force`；它不
提升权限、不放宽允许目录，也不接受 Agent 自定义 perf 参数。

同一轮加入了 Analysis 内容摘要、Collection→输入哈希绑定、分析前后输入身份复核和
`verify-analysis`。因此类似问题如果再次造成 Frame/权重/百分比/事件来源不自洽，会在
交给 Agent 前失败关闭；合法但不完整的数据则标记 `partial` 并携带禁止结论。

## KI-2026-08-14：cap_perfmon PID 绑定与项目启动存在时序窗口（已修复）

- 原问题一：`cap_perfmon` Python Broker 在启动 perf 前核验 PID 所有者和启动时间，但在
  perf 真正附加前，数值 PID 仍可能被内核复用；Rust Helper 已有启动屏障，默认模式没有
  同等的附加后复核；
- 原问题二：项目启动器提交计划后固定等待 200ms 就放行程序。这只是时间猜测，慢机器可能
  尚未附加，极短程序也可能在采集真正开始前结束；
- 修复：两条路径都用 perf control fd 以 `-D -1` 禁用事件启动，收到有界控制 ACK 后再次
  核验计划绑定的 PID/UID/启动时间，随后才 `enable`。最初修复使用 `ping`；当前代码在
  KI-2026-08-26 后改用公开支持的幂等 `disable`。身份变化、ACK 异常、超时和多余帧全部
  安全拒绝，不会发布半成品；
- 项目握手：公共 Broker 协议升级为 `1.1`，Python/Rust 私有 Helper 协议升级为 `1.2`。
  回执同时绑定 `request_id`、`plan_id` 和目标 PID；普通用户启动器只有在验证回执后才
  `exec` 已确认的项目程序；
- `event_source=auto` 时，硬件可用性 probe 会让 bootstrap/Gate 继续暂停，且绝不发送 ready；
  零计数、unsupported、not-counted 都会保守选择软件事件，需要硬件证据时应显式使用
  `hardware_required`。只有最终选中的正式 profile 会发送就绪回执；探测仍计入原授权时长，
  最多 250ms。
- MCP 现在把会阻塞的项目运行器注册为同步工具，由 SDK 在线程中执行，不再堵塞异步会话；
  启动器会给已经完成的短程序一个有界自然退出/回收窗口，集成测试也改为核对 bootstrap
  命令身份，不再依赖固定 sleep。该修复消除了 CI 负载下偶发的 10 秒超时，没有提高全局
  pytest 超时掩盖问题。

这不会把项目命令、参数或环境交给 Collector，也没有增加 root、sudo、sysctl 或跨 UID
权限。旧 Broker/Helper 不与新协议协商；升级两个同版本 DEB 后必须运行
`sudo perflens-admin upgrade` 重启配套服务。

## KI-2026-08-14：独立调试文件只按路径存在性选择（已修复）

- 原现象：ELF 检查器会列出 `.gnu_debuglink` 和 Build ID 的候选路径，但解析器使用前只
  检查“文件存在”，没有证明候选确实属于当前二进制；错误或被替换的调试文件可能产生
  错误源码归因；
- 修复：`.gnu_debuglink` 候选必须匹配 ELF 中记录的 CRC32，Build ID 目录候选必须包含
  相同 Build ID；在调用 `addr2line`/`llvm-symbolizer` 前会再次检查。候选失配时回退到
  身份匹配的原始 DSO；如果原始 DSO 也已改变，则明确拒绝，不猜测源码位置；
- 边界：CRC32 是 GNU debuglink 规定的兼容校验，不是通用密码学签名；Build ID 也不是
  发布者签名。它们用于阻止误配和常见替换，不替代软件供应链签名验证。

## KI-2026-08-12：record 成功，但分析报 CPU 属性缺失（已修复）

- 已确认影响范围：已撤回的部分同版本 `v0.2.0` 包中，`cap_perfmon` Python 采集路径以及
  `paranoid3_helper` 软件降级后生成的 `cpu-clock` `perf.data`；修复同时覆盖软件和硬件
  record，文本 Profile 不受影响；
- 现象：Collection 显示 record 已成功并生成数 MB 证据，但随后
  `analyze_collection` 返回 `EXTERNAL_TOOL_FAILED`。底层 `perf script` 提示
  `Samples ... do not have CPU attribute set` 和 `Cannot print 'cpu' field`；
- 根因：两条 Collector 路径的固定 `perf record` 参数没有完整加入 `--sample-cpu`，而 PerfLens 的
  `perf script` 适配器要求输出每条样本的 CPU 字段；
- 新采集修复：Python Collector 与 Helper 现在对硬件和软件 record 都固定加入
  `--sample-cpu`；参数仍完全由类型化计划生成，未开放任意 perf 参数；
- 旧证据兼容：分析器只在识别到上述精确错误时，自动去掉 `cpu` 字段重试，并写入
  `MISSING_SAMPLE_CPU` 警告。旧文件仍可用于热点、调用路径和源码归因，但不能做逐 CPU
  分布分析；其他 `perf script` 失败不会被吞掉。

这是采集参数与转换字段不一致，不是 `perf_event_paranoid=3` 或 VMware PMU 自动降级
失败。替换同版本 `v0.2.0` 包后，新采集会保留 CPU 身份；已经生成的受影响文件无需删除。

## KI-2026-08-12：项目负载授权易漏传，Agent 失败后越过原授权范围（已修复）

- 原现象：用户已经确认当前项目工作负载，但 Agent 调用 `collect_project_workload` 时
  漏传固定授权值，服务端正确返回 `Project execution requires explicit per-call
  authorization`；随后 Agent 错误地改用 shell 后台启动、直接 `perf`、已有 PID 计划、
  Callgrind 或参数扫描；
- 安全边界：一次项目负载授权只覆盖已确认的可执行文件、参数、模式和上限。它不授权
  shell/`timeout` 包装器、直接 perf、已有 PID 附加、Callgrind、参数扫描、不同参数或
  额外正确性命令。`PID attachment is disabled by server policy` 在没有显式开启已有 PID
  附加时是预期拒绝，不是 Collector 故障；
- 修复：MCP 输入 Schema 把 `authorization` 收紧为唯一固定值
  `I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION`；服务说明、错误下一步和 Skill 都要求在
  已授权范围内纠正该字段并只重试同一个工具，不允许换执行通道绕过；
- 证据归属：`inspect_collection_capabilities` 描述普通 MCP 进程的本地能力。在
  `perf_event_paranoid=3` 下显示 `blocked`，不等于独立 Collector 也受阻，也不是实际
  软件降级原因。Collector 返回的 `actual_event_source`、`fallback_used` 和
  `fallback_reason` 才是本次采集来源；例如 VMware 上常见的准确原因是
  `hardware_probe_produced_no_usable_counts`；
- 报告口径：Callgrind 的 `Ir` 是模拟/插桩得到的指令引用占比，不是 PerfLens
  `cpu-clock` record 的 CPU self 百分比。只有明确标注工具与单位后才可共同作为候选证据。

用户不需要记住或复述固定授权串；Agent 在用户明确确认精确工作负载后负责填写。若同一
工具纠正后仍失败，应保留并报告错误，而不是自行扩大执行范围。

## KL-2026-08-09：部分 VMware/混合架构主机的硬件 PMU 返回零计数（已提供自动降级）

- 现象：软件事件 `task-clock` 等可以计数，但 `cycles`、`instructions` 在持续 CPU 负载下
  仍返回 0，或 `perf` 报 `not supported`、`not counted`、`ENOMEM`；
- 边界：这通常是虚拟 PMU 暴露、宿主机 Hyper-V/VBS、VMware 与 Intel 混合 P/E 核 PMU
  兼容问题，不是来宾 CPU 算力不足，也不能由 root 权限修复；
- 当前处理：`record`/`stat` 默认采用 `event_source=auto`。Collector 用最多 250ms 的
  同 PID 固定探测判断硬件计数是否有用；失败后，`stat` 使用固定软件事件，`record`
  使用 `cpu-clock`，并在结果和中文摘要中明确提示降级；
- 仍可完成：CPU 时间、上下文切换、迁移、缺页、on-CPU 热点、调用路径、源码定位、
  火焰图以及同事件来源的前后对比；
- 不能宣称：IPC、硬件缓存未命中率、分支未命中率和其他微架构结论。

需要硬件证据的实验应选择 `hardware_required` 并让失败保持可见；已知 PMU 不可用且需要
稳定 A/B 时选择 `software_only`。不要把一份 hardware 基线与一份 software 候选结果
直接比较。仍可在完全关机后调整 VMware vPMC/宿主虚拟化设置，但 PerfLens 的软件降级
不再要求用户先解决该平台问题才能继续常规性能优化。

## KI-2026-08-10：Helper 的 stat 成功但 record 无法合成目标映射（已修复）

- 影响范围：已撤回的 `v0.2.0` `paranoid3_helper` 原生包，其中 root Helper unit 只包含
  `CAP_PERFMON` 与 `CAP_SYS_ADMIN`；默认 `cap_perfmon` 和普通组件不受影响；
- 现象：明确使用 `--event-source software_only` 的 `verify-collector` stat 已成功，但
  `accept-collector` 进行软件 record 时仍返回 `EXTERNAL_TOOL_FAILED`。等价的临时
  `perf record` 在两项 capability 下失败，加入 `CAP_SYS_PTRACE` 后能实际写出采样；
- 根因：`CAP_PERFMON` 负责 performance event 访问，但这条附加 PID 的 `perf record`
  路径还需要 ptrace 等价访问，才能读取已经授权目标的进程映射并合成可用采样元数据；
  stat 成功没有覆盖该路径；
- 修复：重新发布的同版本 Helper unit 上限精确为 `CAP_PERFMON`、`CAP_SYS_ADMIN` 和
  `CAP_SYS_PTRACE`。类型化 PID 协议、目标 UID/启动时间、过期、单次消费、事件/时长/输出
  上限和固定 spool 均不改变；Agent、Skill、MCP 与 Python Broker 不增加 capability；
- 升级安全：`perflens-admin upgrade --dry-run` 会在 `helper_capability_expansion` 中显示
  `CAP_SYS_PTRACE`。正式升级在没有 `--acknowledge-privileged-helper-risk` 时，会在写 unit
  和重启服务前拒绝。

安装替换包后执行：

```bash
sudo perflens-admin upgrade --dry-run
sudo perflens-admin upgrade --acknowledge-privileged-helper-risk
perflens accept-collector --authorize-host-acceptance
```

旧参数 `--acknowledge-cap-sys-admin-risk` 仍兼容，但新指南使用覆盖完整边界的通用名称。

## KI-2026-08-10：Helper 将 Linux perf 的 NUL 结尾 ACK 误判为失败（已修复）

- 影响范围：已撤回的 `v0.2.0` `paranoid3_helper` 原生包；默认 `cap_perfmon` 模式
  不经过该私有 Helper 协议；
- 现象：服务健康握手通过，策略也允许固定软件事件，但 `accept-collector` 或明确指定
  `--event-source software_only` 的 `verify-collector` 仍立即返回 `EXTERNAL_TOOL_FAILED`；
  Helper spool 只出现已消费计划标记，没有性能产物；
- 根因：perf 的 control fd 文档把完成响应写作 `ack\n`，Linux 6.12 实现却按 C 字符串
  大小写出 `ack\n\0`。旧 Helper 第一次按行读取后把 NUL 留在缓冲区，导致下一次响应被
  读成 `\0ack\n` 并安全拒绝；只写 `ack\n` 的测试替身没有覆盖真实帧；
- 修复：重新发布的 `v0.2.0` 对 ACK 使用最多 16 字节的严格二进制解析，只允许响应前
  存在实现产生的 NUL，其他内容和超长响应仍拒绝；当时的修复仍使用 `ping`，当前代码在
  KI-2026-08-26 后改用带 ACK 的幂等 `disable`，并继续在启用事件前重新校验 PID 所有者和
  启动时间；
- 回归测试：测试替身现在逐次发送真实的 `ack\n\0`，并覆盖连续响应跨帧时遗留 NUL 的
  情况。

这是 Helper 协议兼容性问题，不是 `perf_event_paranoid=3`、软件事件策略或 VMware PMU
降级失败。安装重新发布的同版本包并运行 `sudo perflens-admin upgrade` 后，再执行普通用户
验收；无需降低 sysctl，也不要给 Agent、MCP 或 Python Broker 增加权限。

## KI-2026-08-07：已撤回的 v0.2.0 Helper unit 无法通过 systemd USER 阶段（已修复）

- 影响范围：已撤回的首批 `v0.2.0` 原生 `perflens-collector` DEB，在 Debian 13 上选择
  `paranoid3_helper`；默认 `cap_perfmon` 模式不受影响；
- 现象：部署健康检查失败，journal 显示 `Failed to drop keep capabilities flag` 和
  `Failed at step USER`；Broker 随后可能因为 Helper 运行目录不存在而在 NAMESPACE 阶段失败；
- 根因：Helper unit 过早设置 `keep-caps-locked`，但 systemd 在 USER 设置阶段仍需清除
  `PR_SET_KEEPCAPS`，锁定状态使该安全转换被内核拒绝；
- 修复：重新发布的 `v0.2.0` 产物移除冲突的 secure-bit 锁；这项 USER 阶段修复本身没有
  扩权。最终替换 unit 为解决 record 问题使用上文单独说明并要求管理员确认的三项
  capability 边界；Agent、MCP 与 Python Broker 仍不增加 capability。

部署器失败后会撤回本轮新配置、两个 unit 和 Socket，不会留下半部署状态。不要手工修改
已安装包或放宽 systemd 边界；请安装重新发布的 `v0.2.0` 产物，再用原配置重新部署。

## KI-2026-08-07：Helper 将正常的限时 SIGINT 结束误判为失败（已修复）

- 影响范围：已撤回的首批 `v0.2.0` `paranoid3_helper` 实现；
- 现象：部署和认证健康握手均成功，但执行
  `perflens accept-collector --authorize-host-acceptance` 返回 `EXTERNAL_TOOL_FAILED`，技术信息为
  `Privileged perf returned a non-zero result`；
- 根因：到达请求时长后，Helper 会先禁用事件，再向附加 PID 的 `perf` 发送 SIGINT，让它刷新并
  关闭产物；Linux 会把这次正常结束表示为 signal 2/状态 130，旧逻辑却按外部失败处理；
- 修复：重新发布的 `v0.2.0` 只在 Helper 自己成功进入限时关闭路径并发送 SIGINT 时接受该状态。
  提前收到 SIGINT、其他信号、普通非零退出、控制消息失败以及空或不安全产物仍会安全拒绝。

这项修复不会让主机原本不存在的性能计数器变得可用。如果验收继续运行后返回
`PROFILE_PARSE_FAILED`，且所有指标都是 `not_supported` 或 `not_counted`，应检查主机 PMU；虚拟机
通常还需要在虚拟化平台中启用“虚拟化 CPU 性能计数器”。

## KL-2026-08-07：Rust Helper 私有 spool 曾不支持归档和清理（已修复）

- 影响范围：已撤回的 `v0.2.0` 最初实现中的 `paranoid3_helper` 模式；
- 修复状态：重新发布的 `v0.2.0` 产物已修复；
- 原行为：`archive-spool`、`verify-spool-archive` 和 `prune-archived-spool` 明确返回
  `UNSUPPORTED_FORMAT`，避免误读或删除普通 `/var/lib/perflens` 中的文件；
- 修复内容：归档生命周期现在根据已审查的权限模式选择真实 spool，分别验证 Helper
  目录/墓碑的 `root:perflens-internal` 身份和产物的 `root:perflens` 身份，并在 manifest
  中绑定权限模式与 spool 路径。

使用已撤回产物的现有部署应先换装重新发布的 v0.2.0 包，再清理 Helper spool。不要手工
删除未知证据或修改目录权限来绕过检查。

## KI-2026-08-06：DEB 原地升级后入口可能继续加载旧版本字节码

- 影响版本：从 `v0.1.2` 原地升级到 `v0.1.3` 的原生 DEB；
- 修复状态：当前开发分支已修复，将随下一版本发布；
- 现象：`dpkg-query` 显示 `0.1.3-1`，但 `perflens --version` 或其他入口仍显示
  `0.1.2`；
- 根因：可复现 DEB 固定了 Python 源文件时间，旧版遗留的同路径 `.pyc` 可能继续满足
  时间戳/大小校验；旧包又没有在升级配置阶段清理它。

当前开发修复包含两层防护：原生启动器在导入 PerfLens 前禁用写入并把 cache 查找移到
包内不存在的固定隔离前缀，因此不再读取旧的 inline `__pycache__`；主包 `postinst` 还会
在 `configure` 阶段只清理固定 `/usr/lib/perflens` 下遗留的 `.pyc/.pyo` 和空 cache
目录。普通 wheel 不受 DEB maintainer script 影响。

已经遇到问题的 `v0.1.3` 用户可以先确认包版本，然后删除固定运行时中的旧 cache：

```bash
dpkg-query -W -f='${Package} ${Version}\n' perflens perflens-collector
sudo find /usr/lib/perflens -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
sudo find /usr/lib/perflens -depth -type d -name '__pycache__' -empty -delete
hash -r
perflens --version
```

不要删除整个 `/usr/lib/perflens`；它属于已安装的主包。

## KI-2026-08-05：`umask 0002` 导致 Collector 配置被部署器拒绝

- 影响版本：`v0.1.2`；
- 修复版本：`v0.1.3`；
- 状态：已修复；`v0.1.2` 用户仍可使用下方安全临时处理；
- 影响范围：使用 `perflens init --prepare-collector` 或
  `perflens setup --prepare-collector` 新生成的 `collector.toml`；
- 不影响：已经成功安装到 `/etc/perflens/collector.toml` 的系统策略、已有 Profile
  分析，以及不需要 Collector 的只读使用方式。

### 现象

在使用常见协作型 `umask 0002` 的系统上生成 Collector 资产后，普通用户执行预检：

```bash
perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml" \
  --dry-run
```

可能收到：

```text
错误代码: PATH_SAFETY_VIOLATION
阶段: collector_deploy
技术信息: Collector config must be invoking-user/root owned,
non-writable by group/other, and bounded
```

检查时通常会看到配置权限是 `664`：

```bash
umask
stat -c '%a %U:%G %n' \
  "$PWD/perflens-setup/collector-assets/collector.toml"
```

示例输出：

```text
0002
664 link:link /home/link/perflens-bootstrap/perflens-setup/collector-assets/collector.toml
```

### 根因

`v0.1.2` 的 Collector 资产生成器创建文件后没有显式设置最终权限，而是受调用进程
`umask` 影响。基础创建权限 `0666` 在 `umask 0002` 下变成 `0664`，因此同组用户仍可
写入配置。部署器会拒绝任何可被组或其他用户写入的策略文件；这是正确的安全行为，
不应放宽。

### `v0.1.3` 修复

`v0.1.3` 不再依赖调用进程的 `umask`：生成目录固定为 `0700`，
`collector.toml` 固定为 `0600`，systemd unit 和 sysusers 模板固定为 `0644`。
部署器的属主、普通文件、大小以及组/其他用户不可写检查保持不变。

升级到 `v0.1.3` 后，重新运行 `perflens init --update --prepare-collector` 生成的
配置可以直接进行 `perflens-admin deploy --dry-run`。已有且未修改的 v0.1.2 Skill
也会同时从旧目录名安全迁移到 `.agents/skills/perflens` 或
`.claude/skills/perflens`。

### `v0.1.2` 临时处理

在包含 `perflens-setup` 的初始化目录中，以生成该文件的普通用户执行：

```bash
chmod 600 "$PWD/perflens-setup/collector-assets/collector.toml"

stat -c '%a %U:%G %n' \
  "$PWD/perflens-setup/collector-assets/collector.toml"
```

确认结果为 `600 <当前用户>:<当前组> .../collector.toml` 后重新预检：

```bash
perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml" \
  --dry-run
```

预检通过后才正式部署：

```bash
sudo perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml"
```

不要使用 `sudo` 跳过 `chmod`，也不要让配置保持 `664`。正式部署会把经过检查的策略
安装为 root 管理的 `/etc/perflens/collector.toml`。

### 是否每个项目都要处理

不需要。Collector 对同一个 Linux 普通用户是主机级服务，首次部署成功后，该用户的
其他项目只需在项目目录运行：

```bash
perflens init --client codex
```

只有重新生成部署配置并再次执行首次部署时，`v0.1.2` 才可能再次遇到此问题。正常软件
升级使用 `perflens-admin upgrade`，不应重复 `undeploy` 和 `deploy`。

### 修复验收

`v0.1.3` 已满足：

- 生成器显式把 `collector.toml` 设置为 `0600`，不依赖调用者 `umask`；
- 在 `umask 0002` 和更宽松的测试环境中仍生成不可被组/其他用户写入的配置；
- `perflens-admin deploy --dry-run` 可直接接受新生成、未被人工修改的配置；
- 保留部署器现有的属主、普通文件、大小和不可组写安全检查；
- 增加回归测试，防止安装引导与部署器再次产生互相不兼容的权限要求。
