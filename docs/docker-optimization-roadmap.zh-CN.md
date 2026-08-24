# PerfLens v0.3.2 有界 Docker 自动优化合同

[English](docker-optimization-roadmap.md)

状态：v0.3.2 实施合同。只有对应代码、安全拒绝测试和验收均已提交的章节才属于当前可用
能力。v0.3.1 固定镜像采集继续兼容，但不表示下述优化接口已经全部可用。

## 目标与边界

`bounded_optimization_session` 是一次用户确认、绑定当前连接的有界授权：Agent 可构建基线、
按证据采集、只修改已审查的项目路径、最多构建三个候选并完成匹配 A/B。它不是永久放行，
也不授权 commit、push、Tag、Release、任意 Docker 参数或声明上下文之外的访问。

优化会话是 Docker 目标工作流，不是 Collector 权限模式。现有 `cpu_only/full_diagnostics`
功能配置和 `cap_perfmon/paranoid3_helper` 权限模式仍决定可取得哪些 perf 证据。v0.4.0
用户态锁 Adapter 不属于 v0.3.2。

## 项目合同

`perflens init --docker` 生成 schema 1.1 的 `container-workload.toml`，其中
`[optimization]` 默认关闭。schema 1.0 仍作为严格的固定镜像输入读取。更新模式保留已有
用户策略，绝不自动开启构建、网络或扩大路径。

启用优化时必须绑定：

- 明确的 `context_paths` 及其子集 `mutable_paths`；
- 项目内 Dockerfile、target、Linux platform、固定 build args 和完整基础镜像 digest；
- 一个网络层级和可选管理员 Builder 策略身份；
- 现有固定 entrypoint、argv、UID/GID、资源限制、Benchmark 输出/格式/名称和正确性合同；
- 最多三个候选、四次构建、十次 workload 以及一次可恢复重试。

Dockerfile 和依赖锁文件默认不可变；只有显式列入 `mutable_paths` 才可修改，且授权摘要必须
标为高风险。空 Benchmark 对 v0.3.1 式诊断仍合法，但不能授权自动优化，也不能输出
Verified Improvement。

## 计划中的类型化接口

稳定 v0.3.2 必须提供以下 MCP 工具：

- `inspect_docker_optimization_capability`；
- `preview_docker_optimization_session`；
- `authorize_docker_optimization_session`；
- `build_docker_optimization_candidate`；
- `collect_docker_optimization_workload`；
- `compare_docker_optimization_iterations`；
- `revoke_docker_optimization_session`。

必须持久化版本化 `DockerBuildCapabilityArtifact`、`DockerBuildRecipeArtifact`、
`DockerBuildContextArtifact`、`DockerBuildArtifact`、`DockerOptimizationSessionArtifact` 与
`DockerOptimizationIterationArtifact`。确认 token 只留在 MCP 内存；公开产物只保存 receipt
摘要、预算、状态、身份和证据哈希，不保存 token、凭据、宿主绝对路径、Docker 端点路径或
源码内容。

## 构建快照与 Adapter

只有类型化 Build Adapter 能执行固定 Docker/Buildx 操作。Agent、Skill、公共 Broker 和两个
perf Helper 都不能直接得到 Docker Socket，也不能传入任意 Docker 参数。每次操作前后都要
复核 Docker CLI、Buildx 插件、本地 Unix 端点和 Builder 身份。

每次构建只使用从 `context_paths` 生成的私有不可变 tar 快照。快照记录相对名称、普通文件/
目录/符号链接类型、权限、大小和 SHA-256；拒绝绝对或越界路径、绝对或越界 symlink、Socket、
设备、FIFO、Git 元数据、凭据目录以及捕获期间发生身份变化的文件。相对 symlink 只有最终目标
也被快照捕获时才允许。immutable 内容变化终止会话；mutable 内容变化成为候选 Treatment。

Adapter 通过私有 IID 与 metadata 文件取得结果，再独立验证最终 digest、platform、镜像大小、
会话标签、Recipe/Context 摘要和 provenance。清理仅删除能证明由本会话创建、且未被既有 Tag
或其他容器引用的对象；禁止全局镜像或缓存 prune。

## 网络层级

1. `local_only` 为默认：完整基础 digest 必须已在本地，pull=false，构建网络为 none。
2. `pinned_pull`：确认后只允许从管理员 registry 白名单拉取完整 digest，实际构建仍无网络。
3. `admin_builder_network`：只允许管理员预部署、root-owned、身份固定的
   `docker-container` BuildKit Builder。其镜像、网络、proxy/CNI、registry 范围和 Buildx
   source policy 均由管理员提供；PerfLens 不创建或修改 Builder。

永久拒绝 remote Docker Context、host network、insecure/device entitlement、secret/SSH
mount、额外 build context、任意 cache 导入导出、宿主挂载、tag-only 基础镜像、远程 `ADD`
和远程自定义 frontend。联网 A/B 必须绑定相同 Builder、网络策略和解析后的 provenance。

## 授权、预算与 Agent 判断

preview 绑定当前 Recipe、Context、Benchmark、Collector 策略、Builder 策略和全部限制的哈希。
如果结果镜像不存在，只说明确认后需要构建；preview 阶段不得 build 或 pull。authorize 要求
完全匹配 preview 摘要和固定确认 token，创建绑定客户端连接的内存 lease，并拒绝重放。

Agent 不机械执行全部模式：先运行最低成本的正确性/Benchmark 和 `stat`，再根据观测选择
`record`、`sched`、`off_cpu` 或 `lock`。安全拒绝、身份变化或正确性失败不得原样重试；可恢复
的编译或测试失败可以消耗整个会话唯一一次重试。

固定上限为三个候选、四次构建、十次 workload、单次构建 900 秒、累计构建 3600 秒、
workload 活动 1800 秒、硬过期 7200 秒、证据 1 GiB、临时镜像 10 GiB，所有并发均为 1。
record 最长 30 秒、99 Hz；Trace 单次最长 10 秒。任一预算耗尽即停止，不能静默新建会话。

## 匹配 A/B 与 Verified Improvement

A/B 不变量包括基础 digest、Builder/网络身份、Dockerfile 固定配方、target/platform/build args、
命令、资源、Benchmark 合同、Collector 策略、内核、perf 版本和实际事件来源。Treatment 包括
mutable 路径哈希、可执行文件哈希/Build ID 和候选最终镜像 digest。同一授权 Recipe 产生不同
最终 digest 是正常候选变化，不终止会话。

只有正确性通过、Benchmark 目标和参数一致、环境与事件来源一致、达到配置阈值、性能证据支持
假设、没有不可接受的 CPU/内存/I/O/节流转移，并通过哈希、守恒和确定性重放验证，才能输出
Verified Improvement。partial、缺失 Benchmark、正确性失败或任一不变量不匹配只能给候选结论。

## 实施与发布门禁

实施拆成独立审查提交：版本/配置合同；构建 Artifact 与快照；Build Adapter；会话/MCP；匹配
A/B 与 Agent 集成；最终包、宿主机与 Docker 验收。每阶段必须先通过正常、拒绝、边界、lint、
类型、Schema 及相关 Python/Rust 协议测试，才能进入下一阶段。

稳定发布还要求 Python 3.12/3.13、覆盖率至少 85%、可复现 wheel/sdist、两个 DEB、不自动启用
的安装/升级/回滚/卸载 smoke、v0.3.1 宿主机与固定 Docker 回归，以及真实 rootless/rootful
Docker 验收。优化会话和本实施合同都不会创建 v0.3.2 Tag。
