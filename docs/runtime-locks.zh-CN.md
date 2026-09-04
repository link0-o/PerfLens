# PerfLens v0.4.0 用户态锁工作流

简体中文 | [English](runtime-locks.md)

状态：**仓库中已实现为 v0.4.0 预发布能力，尚不属于已发布的 v0.3.2 安装包**。只有
v0.4.0 版本、安装包、真实运行时矩阵和主机门禁全部通过后，才能宣称为稳定发布能力。
当前已发布基线仍是 v0.3.2。

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
  -> collect_runtime_lock_evidence 或 import_runtime_lock_evidence
  -> analyze_runtime_lock_evidence
  -> verify_runtime_lock_analysis
  -> 有界热点/调用路径查询，以及按需比较/诊断
  -> revoke_runtime_lock_session
```

Preview 与授权会绑定项目策略、目标/负载身份、Adapter payload 和工具、测量语义、导入根及
预算。授权只保存在当前 MCP 进程中；持久化产物仅保存 receipt 摘要。MCP 权限弹窗或客户端
allowlist 只是允许调用某类工具，不等于用户已同意解析后的目标。

稳定目标模型刻意保持收窄：

- 由已审阅 Runtime Lock 会话启动的宿主机负载；
- PerfLens 托管临时容器或 Docker optimization 的 baseline/candidate；
- 来自已授权项目相对根的受控导入；
- 仅 Go 可使用显式授权、同 UID、本机字面量 loopback pprof，并绑定 Socket inode 与 PID 身份。

PerfLens 不向任意运行中进程或任意已有容器注入。Native、CPython 和 Java 主动采集只支持
启动时插桩；v0.4.0 不包含 live JVM attach，也不把 eBPF/uprobe 作为稳定路径。

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

独立 verifier 会在私有来源可用时重放转换，并校验来源/规范化摘要、事件配对与时间顺序、
目标/上下文隔离、分页以及次数/时长守恒。`partial` 表示证据仍可在明确限制内使用，不会被
自动升级为根因或 Verified Improvement。

## Adapter 兼容矩阵

| Adapter | 仓库 v0.4.0 预发布边界 | 重要限制 |
|---|---|---|
| Native pthread | Debian 12/13 amd64、glibc 2.36/2.41、动态链接 pthread mutex/rwlock/condition；固定 `LD_PRELOAD` 启动插桩；默认 thresholded 1 us，并提供有界 exact | 静态/musl/setuid/file-cap、内联/自定义原子锁、自旋锁和不可见快路径为 partial 或 unsupported；不做 live uprobe/eBPF |
| Java JFR | JDK 17/21/25；启动时 JFR；固定 `balanced` 10 ms 或 `deep` 1 ms；采集 `JavaMonitorEnter`、`JavaMonitorWait`、`ThreadPark`，虚拟线程按 metadata 发现 | 不做 live attach；使用同一 JDK 的 `jfr print --json` 有界转换；阈值以下未记录不能解释为“没有等待”；缺少 acquire/release 时禁止 owner/hold 结论 |
| CPython threading | CPython 3.12/3.13 的公开 `threading.Lock`、`RLock`、`Condition`、`Semaphore`；普通用户启动 bootstrap；默认 thresholded 10 us，并提供有界 exact | 不伪装所有 `_thread` 或 C 扩展锁；GIL、内部锁和应用锁分开；3.13 free-threaded 禁止传统 GIL 结论 |
| Go pprof | Go 1.24-1.27，固定 `go tool pprof -raw`；私有文件 mutex/block Profile；显式启用时支持同 UID 字面量 loopback 宿主 pprof | Docker 默认只用文件后端且不开网络；PerfLens 不开启 runtime Profile rate 或修改源码；mutex/block 保持为独立 cumulative Evidence，其中行表示抽样竞争观测，不虚构 TID、owner 或锁对象 |
| Generic NDJSON | 严格读取 Schema 1.0/1.1 的有界流式受控导入与重放 | 导入源必须声明精确/阈值/抽样/累计语义、时钟、可见面、丢失、owner/hold 来源；格式错误、跨目标、乱序或不守恒输入会被拒绝 |

JDK、Go、async-profiler、DTrace/SystemTap 等属于可选外部依赖。PerfLens 只检测它们，不由
两个核心 DEB 下载或捆绑这些运行时。主原生 DEB 会提供固定、root-owned、无 capability 的
pthread probe 和 Runtime Lock supervisor；安装包本身不会激活它们。

## Docker optimization 集成

仓库 v0.4.0 预发布实现可以在 v0.3.2 Docker optimization 工作流的 Preview 中明确增加一个
已审阅的 Runtime Lock Adapter 和语义。选择后，用户对 Docker optimization 的一次确认同时
覆盖该有界 Runtime Lock 范围，不会再产生第二个隐式授权。PerfLens 在创建容器前检查 Runtime
Lock 预算，且费用只能结算到同一个单次 workload lease。已发布的 v0.3.2 安装包不能请求该扩展。

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
