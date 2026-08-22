# PerfLens v0.3.1 Docker 进程采集与分析路线图

[一次性 Goal 执行合同](v0.3.1-execution-contract.zh-CN.md)

简体中文 | [English](docker-container-roadmap.md)

状态：**计划实现；当前尚不可用**

最后审计：2026-08-21，基于 v0.3.0 宿主机实现

目标版本：`v0.3.1`

本文是 v0.3.1 的设计、实现和发布合同。它不表示当前安装包已经能够主动发现、启动或
采集 Docker 容器。当前 PerfLens 只能稳定处理宿主机 PID，并能对用户已经导出的
`perf.data`、`perf script` 或 folded Profile 做离线分析和源码路径映射。

版本路线固定为：

- `v0.3.0`：完成宿主机 `stat/record/sched/off_cpu/lock` 闭环；
- `v0.3.1`：增加本地 Docker 容器内单个明确进程的采集、分析和容器资源上下文；
- `v0.4.0`：完成 C/C++、Java、Python 和 Go 用户态锁 Adapter。

已经提交的 Runtime Lock 公共合同是 v0.4.0 的前置基础，不代表四类运行时 Adapter
已可用，也不改变 v0.3.1 的 Docker 边界。

## 1. 决策摘要

1. **Docker 是目标运行时，不是第三种 Collector 权限模式。**
   `cpu_only/full_diagnostics` 决定证据能力，`cap_perfmon/paranoid3_helper` 决定
   权限实现，`host/docker` 决定目标所在运行时。
2. **v0.3.1 只支持本地 Linux Docker Engine、cgroup v2 和单个明确进程。**
   不把“容器”自动扩大成所有 PID 或全系统采集。
3. **同时支持现有容器和 PerfLens 托管的临时测试容器。** 托管容器只使用本地已有、
   绑定不可变摘要的镜像，不自动 build 或 pull。
4. **Collector 继续驻留宿主机。** perf 始终附加宿主机 PID；容器 PID 只用于用户交互、
   身份绑定和报告。
5. **Docker Socket 不交给 Collector、Helper、Agent 或 Skill。** 普通用户侧固定 Adapter
   只执行审查过的 Docker 操作，Broker 和 Helper 再使用 Linux 内核身份独立复核。
6. **默认同宿主 UID。** rootful 容器 UID 0 默认拒绝，只有管理员一次性确认专用容器
   跨 UID 风险后才能使用；通用跨 UID 开关继续关闭。
7. **授权不永久保存。** 支持逐次确认和一次 Agent 对话内的有界会话；无响应、超时或
   会话边界不明时必须拒绝，不能默认同意。

## 2. 能力范围

### 2.1 稳定目标

v0.3.1 完成以下闭环：

- 附加到一个已运行 Docker 容器中的明确进程；
- 启动一个由 PerfLens 管理的临时测试容器，并在 workload 第一条指令执行前绑定采集；
- 对目标执行 `stat`、`record`，并在 `full_diagnostics` 已部署时执行
  `sched`、`off_cpu`、`lock`；
- 读取采集前后的容器 cgroup v2 资源上下文；
- 对容器模块进行有界 Build ID、符号和源码路径解析；
- 将容器环境指纹纳入匹配 A/B 和诊断包；
- 通过 Skill 支持“使用 PerfLens 深度优化当前项目的容器负载”这类自然语言请求。

三组配置彼此独立：

```text
功能配置：cpu_only | full_diagnostics
权限模式：cap_perfmon | paranoid3_helper
目标运行时：host | docker
```

选择 Docker 不会自动切换功能配置、权限模式、sysctl 或 capability。

### 2.2 明确不做

v0.3.1 不支持：

- 按整个容器或 cgroup 聚合全部进程的 perf Profile；
- 任意 `docker run`、`docker exec`、Docker CLI 参数或 Docker API 请求；
- Docker Compose、Swarm、Podman、containerd、CRI 或 Kubernetes 编排；
- 远程 Docker Context、SSH/TCP Docker endpoint 或 Docker Desktop VM；
- 自动构建、拉取、推送或删除镜像；
- `--privileged`、`--pid=host`、共享其他容器 PID namespace；
- Docker Socket、宿主根目录、任意设备、任意 capability 或任意宿主目录挂载；
- 容器网络、GPU、跨容器调用链或分布式 APM；
- 在容器内安装 perf、调试包、Agent 或其他依赖。

容器级 cgroup 指标只提供环境上下文，不等于对容器内所有进程做 perf 聚合。

## 3. 用户工作流

### 3.1 项目初始化

计划接口为：

```bash
cd /绝对路径/项目
perflens init --docker
```

它只生成项目级集成和 `perflens-setup/container-workload.toml`，不会启动 Docker、构建
镜像、修改 Docker 用户组或部署系统服务。配置至少声明：

- 工作流类型：附加现有容器或托管临时容器；
- 本地镜像的不可变摘要；
- 容器内绝对 entrypoint、argv 和工作目录；
- 固定 `/workspace` 只读项目挂载；
- PerfLens 管理的可写临时目录；
- 容器用户、CPU、内存、PIDs 和网络策略；
- 首选授权模式；
- 正确性检查和 Benchmark 输出约定。

项目配置可以保存推荐项，不能保存永久执行授权。

### 3.2 附加现有容器

用户提供容器名称或 ID；容器 PID 可以省略。固定 Docker Adapter 先以普通用户执行
有界、只读发现：

1. 使用固定格式的 `docker container inspect` 解析完整容器 ID、镜像 ID、运行状态和
   init 宿主 PID；
2. 使用固定参数的 `docker container top` 取得容器成员的宿主 PID 候选；
3. 从 `/proc/<pid>/status` 读取 `NSpid`，从 `/proc/<pid>/ns/*` 固定 namespace inode，
   并绑定 `/proc/<pid>/stat` 启动时间和 cgroup v2 inode；
4. 对候选做短时 CPU 增量观察，只向 Agent 返回容器 PID、可执行文件名和 CPU 增量；
5. 唯一或明显主导的候选可以自动推荐；多个合理候选必须在本轮授权摘要中列出，由用户
   确认一次。

容器重启、PID 复用、目标退出、namespace/cgroup 改变或 Docker 名称解析到不同完整 ID
时，旧目标和旧授权立即失效。

这里授权的是一个具体服务实例：完整容器 ID、容器启动身份、目标进程 PID/启动时间，
以及 namespace/cgroup 身份共同构成会话目标。任一身份发生重大变化，都可能表示目标
已经不再是用户最初确认的服务，因此不能自动迁移授权。

现有容器默认推荐 `per_run`，因为它可能承载生产服务或其他用户状态。PerfLens 不暂停、
重启、停止或删除该容器。

### 3.3 托管临时容器

托管工作流只使用本地已经存在并固定到镜像摘要的镜像。它通过类型化
`ContainerWorkloadSpecArtifact` 派生固定 Docker 参数，不接受用户提供的 Docker 参数串。

托管临时容器授权绑定稳定的 `ContainerWorkloadSpecArtifact`，而不是某一次运行实例的
容器 ID 或 PID。稳定模板至少绑定项目根及只读挂载范围、镜像摘要、entrypoint、argv、
工作目录、网络和资源限制、允许的采集模式、会话预算与清理策略。

每轮 A/B 可以创建新的容器实例，并产生新的完整容器 ID、宿主 PID、容器 PID、启动时间、
namespace inode 和 cgroup inode。这些变化是托管工作流的正常生命周期，不会单独终止
`bounded_session`。PerfLens 必须证明新实例由当前会话依据相同 WorkloadSpec 创建，重新
验证全部 Linux 身份，并为本轮派生独立、短期、单次使用的 PID 计划。

默认沙箱：

- 项目根只读挂载到 `/workspace`；
- 可写内容只进入本轮会话的私有 scratch；
- 默认 `network=none`；
- 禁止 privileged、host PID、host network、设备、额外 capability 和 Docker Socket；
- 禁止项目根之外的宿主路径；
- 固定 CPU、内存和 PIDs 上限；
- workload 必须以前台模式运行，不能 daemonize 后丢失目标 PID。

为了采集启动阶段，PerfLens 将包内固定、静态的 Container Gate 只读挂载为临时容器
entrypoint。Gate 先通过私有控制 Socket 等待；Docker 创建容器后，PerfLens 解析并复核
Gate 的宿主 PID，Collector 以禁用事件状态完成绑定，普通用户协调器再允许 Gate 对精确
workload 执行 `execve`。Collector 和 Helper始终只收到 PID 计划，不收到 Docker 命令、
镜像、entrypoint 或环境变量。

会话完成后，只能停止和移除同时满足完整容器 ID、会话 nonce、创建 receipt 和 PerfLens
管理标签的临时容器。任何校验失败都保留容器并报告人工清理命令，绝不猜测或删除用户
已有容器。

在不自动 build 的边界下，修改后的代码通过只读 `/workspace` 和私有 scratch 进入相同
工具链镜像。Python 等解释型负载可直接运行；编译型负载可以在固定容器命令中把产物
写入 scratch，或使用用户在宿主机生成并位于项目根内的构建产物。需要重新构建镜像的
项目必须由用户或 CI 在会话外完成。修改 `/workspace` 中的源码不会终止会话；每轮生成
的新构建产物必须记录摘要。重新构建镜像导致镜像摘要变化时，当前设计要求重新授权。
未来若支持会话内构建，必须另行设计固定构建配方授权，不能把任意镜像变化视为已授权。

## 4. 授权模型

### 4.1 `per_run`

每次 workload 执行前展示目标容器、进程、镜像、命令、挂载、网络、资源限制、采集模式
和清理动作。用户明确确认后才生成单次计划。它是现有容器的默认推荐项。

### 4.2 `bounded_session`

`bounded_session` 的用户语义是：**本次 Agent 对话开始时确认一次，之后在同一对话内
不重复确认。** 它是托管临时容器深度优化的默认推荐项。

流程为：

```text
自然语言优化请求
      ↓
只读解析项目、镜像、命令和能力
      ↓
立即展示一次完整会话授权摘要
      ↓
用户明确同意
      ↓
内存中的会话令牌
      ↓
stat → record/trace → 修改 → 匹配 A/B
```

MCP 和不同 Agent 客户端不一定提供可信、统一的对话 ID或“对话已结束”事件。因此会话
不能只依赖 UI 名称，而必须由 PerfLens 创建内存中的随机会话 ID，并绑定：

- 调用用户 UID、项目根及客户端连接身份；
- 固定镜像摘要、entrypoint、argv、工作目录和挂载；
- 现有容器完整 ID和启动身份，或托管 workload spec 摘要；
- 网络、容器用户和资源限制；
- 允许的 `stat/record/sched/off_cpu/lock` 模式；
- 每次采集的时长、频率、输出和 spool 上限；
- 会话创建时间、硬过期时间和累计预算。

默认累计预算为最多 6 次 workload 执行、最多 20 分钟的 workload 活跃运行时间；trace
单次仍不超过 10 秒。管理员只能进一步收紧这些值。两小时只是一枚令牌在客户端未上报
对话结束时的绝对存活上限，不能替代 6 次/20 分钟执行预算。

会话令牌只保存在内存，不写入项目配置、Artifact、日志或磁盘缓存。每次 workload和采集
仍派生独立、短期、单次使用的子计划；“不重复弹窗”不等于重用计划。

正常会话在以下任一事件发生时立即失效：

- Agent 对话或客户端连接明确结束；
- MCP 进程退出、重启或连接身份改变；
- 用户执行计划中的 `perflens revoke-session`；
- 项目根身份或只读挂载范围、镜像摘要、命令、网络、资源限制或授权范围改变；
- Collector 管理员策略、功能配置或权限模式改变；
- 对现有容器：完整容器 ID、容器启动身份、目标进程启动身份、namespace 或 cgroup 改变；
- 对托管临时容器：新实例不能证明由当前会话依据相同 `ContainerWorkloadSpecArtifact`
  创建，或任一实例身份复核失败；
- 达到管理员策略中的累计执行、采集时间、证据容量或并发上限；
- 达到默认两小时的硬性兜底期限。

托管临时容器每轮产生新的容器 ID 和 PID 不属于上述失效条件。检测到 PID 复用或实例
身份错配时，当前单次采集计划立即失败；PerfLens 重新解析本轮容器身份。只有新身份仍
属于当前会话和同一 WorkloadSpec 时才能生成新的单次计划，否则会话才失效。

硬上限只处理客户端没有可靠上报对话结束的情况；在正常对话内不会定期重新弹出确认。
达到任一上限后必须停止；只有用户明确发起继续并重新授权后才能建立新会话，不能自动
弹窗后把无响应解释为同意。

### 4.3 永久授权明确禁止

项目可以永久保存 workload 配置和推荐模式，但不能保存“以后无条件执行”的授权。
原因包括项目代码和分支变化、镜像标签变化、容器名称复用、Agent 误选目标、仓库提示
注入、Docker 参数校验缺陷以及性能采集对生产负载的资源影响。

Docker daemon 能创建挂载宿主文件系统的高权限容器，因此控制 Docker Socket 的用户
具有很强的主机控制能力。PerfLens 不把无响应或超时解释为同意。参考
[Docker Engine 安全说明](https://docs.docker.com/engine/security/)。

## 5. Docker 与权限边界

### 5.1 固定 Docker Adapter

PerfLens 不引入 Docker Python SDK，也不把 Socket 文件描述符传给 Agent。Adapter 只允许
经过所有者、不可写父目录、解析目标和版本检查的绝对 Docker CLI，并清空会影响 endpoint、
context、插件和 TLS 的环境变量。

读取现有容器时只允许固定模板的 `container inspect` 和固定 `ps` 字段的
`container top`。托管容器额外允许 `create/start/wait/inspect/remove`，但全部参数从严格
Artifact 派生；不得接受任意子命令、格式模板、`ps_args`、Socket 路径或环境变量。

只支持两个本地 Unix Socket 类别：管理员审查的 rootful Socket，以及当前用户的固定
Rootless Socket。Socket/父目录 inode、owner、mode 和 peer 身份在操作前后固定；不接受
`DOCKER_HOST`、自定义 Context、TCP、SSH 或符号链接替换。

Docker inspect/top 只是发现提示，不能成为最终授权依据。Docker 官方 API可以返回容器
信息和容器进程的宿主 PID，但最终身份必须由 Linux内核重新证明。参考
[Docker process API](https://docs.docker.com/reference/api/engine/version/v1.47/)。

### 5.2 Rootless、同 UID 与 rootful

Rootless Docker 中容器 root 会映射到运行 daemon 的宿主用户；userns-remap 则可能映射到
高位 subordinate UID。PerfLens 以实际宿主 UID作为授权事实，不能从容器显示的 UID猜测。
参考 [Docker UID/GID 映射](https://docs.docker.com/engine/security/rootless/uid-gid-mapping/)。

默认允许：

- Rootless Docker 中宿主 UID等于调用用户的目标；
- rootful Docker 中显式以调用用户宿主 UID运行的目标。

默认拒绝 rootful UID 0。管理员可以一次性在 Collector策略中启用计划字段
`allow_rootful_container_targets = true`，并使用独立风险确认。该设置只开放经过完整 Docker
身份验证的容器目标，不会打开通用 `allow_other_target_uids`，也不会使后续采集需要重复
输入 sudo。

rootful `stat/record` 由受限 Rust Helper 执行，并独立验证请求 peer、计划、目标 PID/UID、
启动时间、PID/user/mount namespace和cgroup身份；Python Broker不获得 `CAP_SYS_PTRACE`
或 root。高级 trace仍由独立 Trace Helper执行。旧 Helper 的模式集合继续只有
`stat/record`，不会接收 Docker命令或 Socket。

## 6. 目标身份与协议

计划新增以下版本化公共产物：

- `DockerRuntimeCapabilityArtifact`：Docker CLI、endpoint类别、daemon模式、cgroup版本、
  Rootless/rootful和功能可用性；
- `ContainerTargetArtifact`：不可变容器/镜像身份摘要、容器 PID、宿主 PID/UID/启动时间、
  namespace和cgroup绑定；
- `ContainerProcessInventoryArtifact`：有界、脱敏的候选进程及短时 CPU增量；
- `ContainerResourceContextArtifact`：采集前后 cgroup资源快照、差值、范围和限制；
- `ContainerWorkloadSpecArtifact`：固定镜像、workload、挂载、网络、用户和资源策略；
- `ContainerOptimizationSessionArtifact`：授权模式、绑定摘要、累计预算和失效状态；
- `ContainerRunArtifact`：托管容器生命周期、目标 PID、退出状态和对应 Collection ID。

现有 Collection Plan/Artifact 使用向后兼容的新版本增加可选容器目标摘要；旧 Host PID
产物继续按 Host目标读取。Broker、stat/record Helper和Trace Helper协议分别增加严格的
容器目标 union；旧 peer只能处理 Host PID，遇到容器计划必须明确拒绝，不能忽略新字段。

私有 receipt 保留复核所需的完整容器 ID、Socket身份和cgroup路径；公开 Artifact只保存：

- 容器和镜像身份摘要；
- 容器 PID、目标宿主 PID/UID/启动时间；
- namespace/cgroup inode或不可跨 Artifact关联的摘要；
- Docker Adapter路径、版本、哈希和固定 recipe ID；
- cgroup资源快照和证据质量；
- allowed/forbidden conclusions。

不得保存完整 inspect响应、环境变量、Docker标签、Secret、挂载源、Socket路径、目标外
进程argv或原始cgroup路径。错误和审计日志采用相同脱敏规则。

Broker和所有特权 Helper必须在开始采集前，以及perf完成后，再次检查宿主 PID、UID、
`/proc/<pid>/stat`启动时间、`NSpid`层级、namespace inode和cgroup身份。Linux `/proc`
公开 `NSpid`等namespace层级字段，cgroup v2公开进程归属和资源接口。参考
[Linux `/proc` 文档](https://www.kernel.org/doc/html/latest/filesystems/proc.html)和
[cgroup v2 文档](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)。

## 7. 采集、资源和符号化

### 7.1 perf 与 Trace

perf 始终使用经过复核的宿主 PID：

- `stat/record` 复用现有硬件优先、软件事件降级和证据限制；
- `sched/off_cpu/lock` 复用 v0.3.0目标内核过滤 Trace Helper；
- 不使用 `perf -a`、所有 CPU、整个 cgroup或所有容器进程作为隐式替代；
- 容器内没有 perf也不影响宿主 Collector；PerfLens不会进入容器安装工具。

### 7.2 cgroup v2 上下文

PerfLens 对已经固定 inode的容器 cgroup目录做采集前后只读快照，至少包括：

- `cpu.stat`、`cpu.max`、`cpuset.cpus.effective`；
- `memory.current`、`memory.max`、`memory.events`、可用的 memory pressure；
- `io.stat`和可用的 I/O pressure；
- `pids.current`和`pids.max`。

解析必须有文件、行、字段、设备和总字节上限。cgroup v2文档指出`cgroup.procs`读取期间
可能出现重复或PID回收，因此成员关系不能仅依赖一次文本列表；必须和目标启动身份、
namespace及cgroup inode共同验证。

这些计数属于整个容器。报告可以直接陈述“观察到节流/内存事件”，但不能把容器总量
伪装成目标进程独占开销，也不能仅凭相关性声称代码根因。

### 7.3 容器符号与源码

`record` 解析继续以 Build ID和验证过的模块偏移为准。模块位于容器rootfs时：

1. 固定目标 mount namespace和`/proc/<host-pid>/root`目录身份；
2. 只打开perf映射实际引用的模块，不遍历或导出完整rootfs；
3. 对模块数量、单文件、总字节、符号查询和调试文件设置上限；
4. 将容器内源码路径映射到用户授权的workspace，复用现有SourceLocator；
5. 目标退出或文件身份变化时标记`partial`，不得从路径或地址猜测模块。

公开证据只保存模块Build ID、内容哈希、容器内路径摘要和workspace映射结果，不保存
容器中的Secret、配置文件或无关文件。

## 8. 分析与 A/B 质量

诊断报告必须同时披露：

- Docker目标类型、镜像身份摘要和容器用户映射；
- 容器 PID与宿主 PID绑定是否通过；
- 实际事件来源、fallback 和 PMU 限制；
- cgroup资源限制、采集区间内增量及其容器级范围；
- module/source解析覆盖率；
- 容器重启、目标退出、事件丢失或资源截断；
- 允许与禁止得出的结论。

匹配 A/B 至少要求以下环境字段相同：

- 镜像摘要和Container Gate摘要；
- entrypoint、argv、工作目录、挂载布局和网络模式；
- 容器用户、CPU、cpuset、内存、I/O和PIDs限制；
- 宿主内核、perf、Collector 配置、事件来源和采样设置；
- workload参数、输入摘要和正确性断言。

不同的临时容器 ID不会自动使A/B不可比；容器环境指纹必须一致。源码或构建产物摘要
可以作为被比较的处理变量。只有正确性通过、环境匹配且有绝对指标的前后测量才能写成
`Verified Improvement`。

## 9. CLI、MCP 与 Skill 计划

计划中的用户入口：

```bash
perflens init --docker
perflens container status --project /绝对路径/项目
perflens accept-container --container <名称或ID>
perflens revoke-session
```

`perflens init`可以只读检测Dockerfile或容器配置并提示`--docker`，但不能静默启用Docker
执行权限。MCP新增的容器工具必须使用类型化Schema，并分别控制：

- 容器能力/进程发现；
- 附加现有容器；
- 启动托管临时容器；
- 创建或撤销优化会话；
- 采集、分析和读取脱敏 Artifact。

读Docker身份不能自动授权执行容器；附加现有容器不能自动授权托管启动。Skill按以下
顺序工作：

```text
读取项目和Docker能力
      ↓
解析精确容器workload或现有目标
      ↓
生成一次授权摘要
      ↓
stat
 ├─ CPU密集 → record
 ├─ runnable异常 → sched
 ├─墙钟长但CPU不高 → off_cpu
 └─竞争候选 → lock
      ↓
修改代码 + 正确性检查 + 同条件A/B
```

Agent只能在本次授权会话和管理员策略交集内选择最小必要证据，不能因为“深度优化”四个
字自动扩大镜像、命令、挂载、网络、目标、时长或权限。

## 10. 实施顺序

后续代码按独立、可回滚提交完成：

1. Docker能力、目标、资源、workload、会话和run公共合同及Schema；
2. 固定Docker inspect/top Adapter、Socket身份固定和有界脱敏解析；
3. `/proc`、NSpid、namespace、cgroup v2和PID复用目标解析器；
4. cgroup v2资源快照、差值、质量模型和verifier；
5. 现有容器单PID的plan→policy→broker→artifact路径；
6. 静态Container Gate、托管临时容器启动器和失败清理；
7. `per_run`与对话级`bounded_session`、内存令牌、撤销和硬上限；
8. rootful容器专用策略、Helper独立复核和风险确认；
9. 容器模块/Build ID/源码映射及诊断包；
10. CLI、MCP、Skill自动路由和匹配A/B；
11. DEB、升级/卸载、真实Docker矩阵和中英文发布文档。

每一步必须先通过拒绝路径和当前里程碑测试，不能在身份与Artifact合同之前先给MCP开放
Docker执行。

## 11. 测试与发布门槛

### 11.1 确定性和安全测试

至少覆盖：

- Docker inspect/top畸形、超限、未知字段、非UTF-8、工具替换和Socket替换；
- Docker名称复用、完整ID变化、容器重启、PID复用、目标退出和动态线程；
- NSpid、namespace、cgroup、UID和启动时间任一错配；
- rootful未确认、通用跨UID、host PID namespace和共享PID namespace拒绝；
- 任意 Docker 命令/参数、远程 endpoint、build/pull、privileged、设备、capability、Socket 与
  宿主路径挂载拒绝；
- 会话跨项目/连接/用户/容器重放、MCP重启、显式撤销、硬过期和预算耗尽；
- 公开Artifact、错误和日志中没有环境变量、标签、挂载源、Socket路径或目标外argv；
- cgroup字段、计数差值、溢出、重置、截断和容器级范围；
- module/rootfs symlink、目标退出、Build ID错配和source path逃逸；
- 只清理本轮创建的容器，任何身份不确定时不执行remove。

### 11.2 真实环境矩阵

发布前必须在Debian 12/13、cgroup v2、systemd/cgroupfs驱动下验证：

- Rootless Docker；
- rootful Docker中与调用用户同宿主UID的进程；
- 管理员显式开放的rootful UID 0；
- 现有容器和托管临时容器；
- Python、C、C++解释型和编译型负载；
- `stat/record`与`full_diagnostics`三个Trace模式；
- 硬件 PMU 可用和软件事件降级；
- CPU quota/throttling、cpuset、memory事件、I/O和PIDs限制；
- 目标启动阶段、短进程、动态线程、容器重启和失败清理；
- 容器内模块符号、workspace 源码映射和匹配 A/B。

### 11.3 包和升级

两个DEB继续不依赖、不安装、不启动Docker，不创建Docker配置，不把任何用户加入Docker
组，也不自动启用项目Docker集成或rootful目标。`0.3.0 → 0.3.1`升级保持现有Host目标和
Collector策略；管理员和项目用户分别显式启用Docker与rootful边界。

只有合同、解析、Broker/Helper拒绝路径、两种工作流、对话会话、cgroup上下文、符号化、
真实Docker矩阵和包升级/卸载全部通过，v0.3.1才能宣称稳定Docker进程支持。缺少任一
核心工作流时必须缩小发布声明或推迟版本，不能用“支持Docker”掩盖部分实现。
