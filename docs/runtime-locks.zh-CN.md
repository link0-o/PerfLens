# PerfLens v0.4.0 用户态锁工作流

简体中文 | [English](runtime-locks.md)

状态：**已实现为 v0.4.0 发布候选，尚不属于已发布的 v0.3.2 安装包**。版本与可复现候选
安装包已准备好，但真实运行时矩阵、主机、远端 CI 与 Tag 门禁仍须通过后才能发布。当前
已发布基线仍是 v0.3.2。当前证据见[《v0.4.0 发布候选就绪记录》](v0.4.0-release-readiness.zh-CN.md)。

Runtime Lock 是面向语言级等待与竞争的确定性证据链。它不会把每个 futex 当成语言锁，
不会在来源没有提供时猜测 owner 或持锁区间，也不会把抽样或累计 Profile 写成精确事件。

## 启用项目

```bash
cd /项目的绝对路径
perflens init --runtime-locks

# 需要托管/优化 Docker 工作流时组合启用：
perflens init --docker --runtime-locks
```

初始化会生成 `perflens-setup/runtime-locks.toml`，并更新项目级 MCP 与 Skill。它只启用能力
发现，不会插桩或附加进程、导入证据、启动负载、访问 pprof 或授予执行权限。
`perflens init --update` 会保留已经审阅的策略，不会自动扩大 Adapter、目标范围、导入根或预算。

默认策略把会话限制为最多 6 次负载、1,200 秒活动时间、3,600 秒硬过期、每份原始/公开
产物 64 MiB、会话证据 512 MiB、单 Adapter 并发 1、普通采集 30 秒，以及 exact 模式
3 秒/20,000 事件。这些都是上限，不代表 Agent 应机械消耗全部次数或 Adapter。

## 授权与证据流程

MCP 工作流为：

```text
inspect_runtime_lock_capability
  -> preview_runtime_lock_session
  -> 展示精确目标、Adapter、语义、payload、工具、路径和预算
  -> 等待用户一次新的明确确认
  -> authorize_runtime_lock_session
  -> collect_runtime_lock_evidence
     -> 使用 Run 绑定的 Analysis + Verification ID 调用 verify_runtime_lock_analysis
  或 import_runtime_lock_evidence
     -> analyze_runtime_lock_evidence -> verify_runtime_lock_analysis
  -> 有界热点/调用路径查询，以及按需比较/诊断
  -> revoke_runtime_lock_session
```

主动采集会在一条 fail-closed 流水线内生成 Run、Analysis、Verification 和私有来源重放
receipt。私有来源清理后再次验证时，必须同时传入 Run 保存的两个 ID，以复核持久化 receipt。
不要把已采集的公开 Evidence 当作新导入再次分析；单靠公开 Evidence 无法重建私有来源 receipt。
如需生成诊断 Bundle，也要传入同一个 Run 绑定的 Verification ID。

成功采集的返回引用会直接给出不可变 Run Finalization 的 ID/内容摘要，以及完成结算的 Session
Artifact ID/revision。撤销 Session 前应读取这份很小的 Finalization Artifact，确认
`outcome=completed` 且绑定同一个 Run。随后显式撤销会生成一个更晚的终态 Session revision，
其中 `settlement_finalization_id=null`；该字段只表示“这个 revision 没有结算新操作”，不会删除
或否定前一个 Run Finalization。报告必须使用采集返回的 Finalization ID，不能根据终态的 null
误报“没有 Finalization”。Evidence 的 `quality.status` 与 Run 的 `quality_status` 属于不同合同
层级，也必须分别报告。

Preview 与授权会绑定项目策略、目标/负载身份、Adapter payload 和工具、测量语义、导入根及
预算。授权只保存在当前 MCP 进程中；持久化产物仅保存 receipt 摘要。MCP 权限弹窗或客户端
allowlist 只是允许调用某类工具，不等于用户已同意解析后的目标。

每个宿主机 Adapter/工作负载仍有自己独立的精确 Preview 与 Session。用户明确要求有界验收
矩阵时，Agent 可以先创建全部独立 Preview，完整展示每个子项的 ID/hash、精确范围、计划采集
参数、执行顺序、合计上限和失败策略，然后只等待一次、由用户对整组已展示内容作一次新的
明确确认。确认后必须立即逐个授权，并串行采集。这是一次人工确认覆盖多个独立授权调用，
不是原子批事务，也不是一个 Session。任一 Preview 过期/变化或授权失败都会停止整批；替换
Preview 必须重新完整展示并由用户再次统一确认。客户端自身的工具权限弹窗属于另一层机制。

Capability 检查与 Preview 都是只读操作，不允许 Agent 在此期间直接启动或冒烟运行目标；即使
不带 profiler 参数也不行。只有完成上述确认和授权后，原生采集工具才能启动精确工作负载。

稳定目标模型刻意保持收窄：

- 由已审阅 Runtime Lock 会话启动的宿主机负载；
- PerfLens 托管临时容器或 Docker optimization 的 baseline/candidate；
- 来自已授权项目相对根的受控导入；
- 仅 Go 可使用显式授权、同 UID、本机字面量 loopback pprof，并绑定 Socket inode 与 PID 身份。

PerfLens 不向任意运行中进程或任意已有容器注入。Native、CPython 和 Java 主动采集只支持
启动时插桩；v0.4.0 不包含 live JVM attach，也不把 eBPF/uprobe 作为稳定路径。

宿主机 CPython 授权会绑定规范化解释器、包内 bootstrap，以及不可组写的 Runtime Home 目录
身份。非特权 supervisor 只接收这些已经打开的描述符，并自行生成固定
`PYTHONHOME=/proc/self/fd/<n>`；因此可支持安全安装的可重定位 CPython，同时不接受 Agent
传入任意环境变量，也不退回按路径执行。Runtime Home 被替换或可写时主动采集显示
`unavailable`，受控导入与离线分析仍可使用。

## 证据语义

Runtime Lock Evidence Schema 1.1 可以表示 OS 线程、Java 平台/虚拟线程、Go goroutine 和
进程聚合。一份 Evidence 只能使用一种语义：

- `exact`：在有界可见面内，记录到的事件是精确事件；
- `thresholded`：只保留达到配置时长阈值的事件；
- `sampled`：事件是抽样观测，不是精确竞争次数；
- `cumulative`：运行时 Profile 提供累计聚合，而不是逐事件日志。

不同 JFR 阈值以及 Go mutex/block Profile 必须保持为独立 Evidence。Analyzer 可按 opaque
锁 ID、执行上下文、调用路径、等待结果和锁类型聚合，并守恒 omitted 数量与权重。锁 ID
只在单个 Artifact 内稳定，且不会公开来源地址。精确 owner 与持锁时间必须来自真实、可配对
的来源证据。
JFR Evidence 会明确发布 `quality.lost_source_bytes`（包括 0）；因为
`jdk.DataLoss.amount` 的单位是字节，不能伪装成事件计数。

所有公开调用路径的帧序列统一为“根/调用者 → 叶/被调用者”，不受来源运行时原生序列化方向
影响。Go pprof 的 `profile_kind` 是 Preview 中精确绑定的字段（`mutex` 或 `block`），会进入
内容绑定的授权摘要；采集请求必须重复同一值，Run 也会持久化该值。缺失或不同的值会在启动
工作负载前被拒绝。

独立 verifier 会在私有来源可用时重放转换，并校验来源/规范化摘要、事件配对与时间顺序、
目标/上下文隔离、分页以及次数/时长守恒。`partial` 表示证据仍可在明确限制内使用，不会被
自动升级为根因或 Verified Improvement。

## Adapter 兼容矩阵

| Adapter | 仓库 v0.4.0 预发布边界 | 重要限制 |
|---|---|---|
| Native pthread | Debian 12/13 amd64、glibc 2.36/2.41、动态链接 pthread mutex/rwlock/condition；固定 `LD_PRELOAD` 启动插桩；默认 thresholded 1 us，并提供有界 exact | 静态/musl/setuid/file-cap、内联/自定义原子锁、自旋锁和不可见快路径为 partial 或 unsupported；不做 live uprobe/eBPF |
| Java JFR | 目标矩阵 JDK 17/21/25；启动时 JFR；固定 `balanced` 10 ms 或 `deep` 1 ms；采集 `JavaMonitorEnter`、`JavaMonitorWait`、`ThreadPark`，虚拟线程按 metadata 发现 | 不做 live attach；使用同一 JDK 的 `jfr print --json` 有界转换；阈值以下未记录不能解释为“没有等待”；缺少 acquire/release 时禁止 owner/hold 结论；本地发布证据当前覆盖 JDK 21/25，JDK 17 仍阻断发布 |
| CPython threading | CPython 3.12/3.13 的公开 `threading.Lock`、`RLock`、`Condition`、`Semaphore`；普通用户启动 bootstrap；默认 thresholded 10 us，并提供有界 exact | 不伪装所有 `_thread` 或 C 扩展锁；GIL、内部锁和应用锁分开；3.13 free-threaded 禁止传统 GIL 结论，且在真实环境通过前仍阻断发布 |
| Go pprof | 目标矩阵 Go 1.24-1.27，固定 `go tool pprof -raw`；私有文件 mutex/block Profile；显式启用时支持同 UID 字面量 loopback 宿主 pprof | Docker 默认只用文件后端且不开网络；PerfLens 不开启 runtime Profile rate 或修改源码；mutex/block 保持为独立 cumulative Evidence，不虚构 TID、owner 或锁对象；当前只有 Go 1.24 具备所需本地 Golden，1.25-1.27 保持 `partial` 并阻断发布 |
| Generic NDJSON | 严格读取 Schema 1.0/1.1 的有界流式受控导入与重放 | 导入源必须声明精确/阈值/抽样/累计语义、时钟、可见面、丢失、owner/hold 来源；格式错误、跨目标、乱序或不守恒输入会被拒绝 |

JDK、Go、async-profiler、DTrace/SystemTap 等属于可选外部依赖。PerfLens 只检测它们，不由
两个核心 DEB 下载或捆绑这些运行时。主原生 DEB 会提供固定、root-owned、无 capability 的
pthread probe 和 Runtime Lock supervisor；安装包本身不会激活它们。Java Adapter 从 MCP
Server 的 `PATH` 解析 `java`，再把 `java`、`jfr` 与运行时 payload 固定到同一个可信 JDK
根目录。需要 JDK 17、21 或 25 时，应让客户端启动环境的 `PATH` 优先指向对应 JDK；只设置
`JAVA_HOME` 不会完成选择。使用 Java 17 编译的项目可以直接用其 JDK 17 运行时采集，不需要
强制切换到验收机使用的 JDK 21；但在 JDK 17 真实矩阵通过前，v0.4.0 仍不能正式宣称该项
兼容性验收完成。

Java 转换、重放、发布及身份安全清理全部成功后，私有 JFR recording 和 JSON transcript 会被
删除。如果转换、重放或安全清理以 `adapter_output_invalid` 结束，PerfLens 会有意保留这两个
有界、仅属主可读的私有诊断文件。其字节会计入 Session Evidence 预算，并在 MCP 重启时重新
盘点；该失败不会发布公共 Evidence 或成功 Run。这些隐藏文件是诊断隔离区，不是公共 Artifact，
也不是无界泄漏。运维人员不应把它们当作公共证据归档，只应在所属 MCP 进程停止后进行明确、
具备身份校验的清理。

## Docker optimization 集成

仓库 v0.4.0 预发布实现可以在 v0.3.2 Docker optimization 工作流的 Preview 中明确增加一个
已审阅的 Runtime Lock Adapter 和语义。选择后，用户对 Docker optimization 的一次确认同时
覆盖该有界 Runtime Lock 范围，不会再产生第二个隐式授权。PerfLens 在创建容器前检查 Runtime
Lock 预算，且费用只能结算到同一个单次 workload lease。已发布的 v0.3.2 安装包不能请求该扩展。

`preview_docker_optimization_session` 可接收可选的 `runtime_lock_semantics` 对象，为每个请求的
Adapter 明确选择一种测量语义，例如 `{"native_pthread":"exact"}`。所选 binding 与阈值都会
内容绑定进 Preview。省略该对象时保留由策略推导的兼容默认值；需要特定语义的调用方应始终
传入它，并在确认前核对返回的 scope。

baseline/candidate 比较会绑定精确 Build 内容摘要、Recipe、Builder/网络策略、平台、immutable
上下文、Container Run/Measurement、运行时/工具/payload 身份和资源比较。candidate 镜像摘要
变化只有在固定环境相同且 mutable manifest 确实变化时，才是合法 Treatment。Runtime Lock
单独只能产生 candidate 或 `no_material_change`；最终 `verified_improvement` 仍必须同时通过
外层 Docker A/B 的正确性、Benchmark、perf 事件来源、资源转移和确定性重放门禁。

任何后处理或持久化失败都会把父会话的 Runtime Lock 标记为 unavailable 并禁止误导性继续。
身份替换、策略/工具/payload 变化、预算耗尽、撤销或过期均安全失败，不能原样自动重试。

## 离线 CLI

CLI 可以在不启动目标的情况下处理受控证据：

```bash
perflens import-runtime-lock-evidence \
  --input ./perflens-runtime-locks/input.ndjson \
  --output ./runtime-lock-evidence.json

perflens analyze-runtime-lock-evidence \
  --input ./runtime-lock-evidence.json \
  --output ./runtime-lock-analysis.json

perflens verify-runtime-lock-analysis \
  --analysis ./runtime-lock-analysis.json \
  --evidence ./runtime-lock-evidence.json \
  --source ./perflens-runtime-locks/input.ndjson \
  --output ./runtime-lock-verification.json
```

输出保持只追加并经过脱敏，不持久化私有原始路径、授权 token、源码内容、原始锁地址、环境
变量或凭据。
