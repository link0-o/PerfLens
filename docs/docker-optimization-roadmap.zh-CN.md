# PerfLens v0.3.2 有界 Docker 自动优化合同

[English](docker-optimization-roadmap.md)

状态：v0.3.2 发布候选接口已经实现，但[已知问题](known-issues.zh-CN.md)中的安全与多客户端
发现尚未解决，因此不能宣称已经达到发布就绪。合同、上下文快照、类型化 Build Adapter、
一次确认会话工具、Build 绑定采集、确定性 A/B 比较及 Agent 策略已经存在；完整的
rootless/rootful Docker 与已安装主机验收也仍是发布门禁。v0.3.1 固定镜像采集继续兼容。

## 目标与边界

`bounded_optimization_session` 是一次用户确认、绑定当前连接的有界授权：Agent 可构建基线、
按证据采集，只允许已审查项目路径中的变化进入构建快照，最多构建三个候选并完成匹配 A/B。
实际文件写权限仍由客户端沙箱控制，不是 PerfLens 自身强制的 capability。该会话不是永久
放行，也不授权 commit、push、Tag、Release、任意 Docker 参数或声明上下文之外的访问。

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

系统包提供 root-owned、只读且为空的 Docker 配置信任锚点。由于 Buildx 必须保存 Builder
选择状态，每个 Preview 会在随机的用户私有 `0700` 目录中创建一个空的运行时配置。它不会
复制用户 Docker 配置、凭据或 Context；每次命令都会重新核对该目录的 inode、owner 和
mode。显式撤销会在能够安全证明归属时立即清理私有运行时状态；Preview/会话过期会立即使
授权失效，并由有界定时器或后续任意交互回收。MCP 连接关闭时也会撤销活动授权并执行相同的
身份核验清理。进程崩溃仍可能留下已证明归属的对象供人工审查；禁止全局 Docker prune。

## 已实现的类型化接口（仍需真实主机验收）

v0.3.2 实现提供以下 MCP 工具：

- `inspect_docker_optimization_capability`；
- `preview_docker_optimization_session`；
- `authorize_docker_optimization_session`；
- `build_docker_optimization_candidate`；
- `collect_docker_optimization_workload`；
- `compare_docker_optimization_iterations`；
- `finalize_docker_optimization_candidate`；
- `revoke_docker_optimization_session`。

实现会持久化版本化 `DockerBuildCapabilityArtifact`、`DockerBuildRecipeArtifact`、
`DockerBuildContextArtifact`、`DockerBuildArtifact`、`DockerOptimizationSessionArtifact` 与
`DockerOptimizationIterationArtifact`，以及最终的 `DockerOptimizationDispositionArtifact`。
确认输入不会持久化；公开产物只保存 receipt 摘要、预算、状态、身份和证据哈希，不保存凭据、
宿主绝对路径、Docker 端点路径或源码内容。

## 构建快照与 Adapter

只有类型化 Build Adapter 能执行固定 Docker/Buildx 操作。Agent、Skill、公共 Broker 和两个
perf Helper 都不能直接得到 Docker Socket，也不能传入任意 Docker 参数。每次操作前后都要
复核 Docker CLI、Buildx 插件、本地 Unix 端点和 Builder 身份。

每次构建只使用从 `context_paths` 生成的私有不可变 tar 快照。快照记录相对名称、普通文件/
目录/符号链接类型、权限、大小和 SHA-256；拒绝绝对或越界路径、绝对或越界 symlink、Socket、
设备、FIFO、Git 元数据、凭据目录以及捕获期间发生身份变化的文件。相对 symlink 只有最终目标
也被快照捕获时才允许。immutable 内容变化终止会话；mutable 内容变化成为候选 Treatment。

Adapter 通过私有 IID 与 metadata 文件取得结果，再独立验证最终 digest、platform、镜像大小、
会话标签、Recipe/Context 摘要和 provenance。Exporter 身份既接受 Buildx 官方的 config
digest/descriptor 投影，也接受旧版仅提供 image digest 的投影；所有已提供 digest 都必须格式
正确，互相矛盾的 config 或 manifest 声明会被拒绝。失败时只保留有界 digest 投影，不保留原始
metadata。清理仅删除能证明由本会话创建、且未被既有 Tag 或其他容器引用的对象；禁止全局镜像
或缓存 prune。

## 网络层级

1. `local_only` 为默认：完整基础 digest 必须已在本地，pull=false，设计目标是构建网络为
   none。Dockerfile 在此层只允许 `RUN --network=none`；格式错误、`default`、`host` 或
   自定义逐条覆盖都会被拒绝。
2. `pinned_pull`：确认后只允许从管理员 registry 白名单拉取完整 digest，实际构建设计为无
   网络，因此同样只允许 `RUN --network=none`。
3. `admin_builder_network`：只允许管理员预部署、root-owned、身份固定的
   `docker-container` BuildKit Builder。其镜像、网络、proxy/CNI、registry 范围和 Buildx
   source policy 均由管理员提供；PerfLens 不创建或修改 Builder。Dockerfile 的
   `RUN --network` 只允许 `none` 或 `default`。

在 `local_only` 中，配置的 digest 可能是本地 image ID，而不是 registry `RepoDigest`；BuildKit
不得因此去 registry 解析它。类型化 Adapter 会为已经验证的本地镜像创建不可预测的会话私有
Tag，只在未链接的派生 Context 中替换已验证的外部 `FROM` 引用，授权 Dockerfile 与原 Context
快照保持不变。Adapter 会再次验证 Tag 身份，要求 Buildx provenance materials 绑定配置 digest，
并且只删除能证明由本次操作创建的 Tag；预先存在、被替换或身份不明确的 Tag 绝不覆盖或删除。

永久拒绝 remote Docker Context、host network、insecure/device entitlement、secret/SSH
mount、额外 build context、任意 cache 导入导出、宿主挂载、tag-only 基础镜像、远程 `ADD`
和远程自定义 frontend。联网 A/B 必须绑定相同 Builder、网络策略和解析后的 provenance。

## 授权、预算与 Agent 判断

preview 会直接公开规范化的项目相对 `context_paths` 和 `mutable_paths`，并将它们与当前 Recipe、
Context、Benchmark、Collector 策略、Builder 策略和全部限制一起绑定哈希。这是知情授权界面；
Agent 不得用“没有可修改路径”等自行推断替换工具返回的路径清单。如果结果镜像不存在，只说明
确认后需要构建；preview 阶段不得 build 或 pull。authorize 要求完全匹配 preview 摘要和固定
确认 token，创建绑定客户端连接的内存 lease，并拒绝重放。

Agent 不机械执行全部模式：先运行最低成本的正确性/Benchmark 和 `stat`，再根据观测选择
`record`、`sched`、`off_cpu` 或 `lock`。安全拒绝、身份变化或正确性失败不得原样重试；可恢复
的编译或测试失败可以消耗整个会话唯一一次重试。

第一次修改前必须先检查基线是否足以分辨预期收益：保留重复原始值，将预期效应与实际离散程度
比较，并要求热点、调用路径、源码或明确的可证伪实验真正指向 `mutable_paths`。如果 partial
Profile 样本稀疏、主要落在不可变测试框架，而且预期收益小于 Benchmark 波动，就应停止改码并
说明如何加强 workload。正确性合同必须覆盖代表性输入和不变量；硬编码唯一预期答案、跳过目标
工作或只针对测量输入特化属于 Benchmark 过拟合，不是性能优化。

普通项目根仍会只读挂载到 `/workspace`，所以每次采集都要求当前 mutable manifest 与所选 Build
完全一致。需要用于噪声判断的重复基线必须在第一次候选编辑前完成；工作区已经推进到候选后，
旧基线 Build 被拒绝采集是证据身份保护，不能当作瞬时错误原样重试。

固定上限为三个候选、四次构建、十次 workload、单次构建 900 秒、累计构建 3600 秒、
workload 活动 1800 秒、硬过期 7200 秒、证据 1 GiB、临时镜像 10 GiB，所有并发均为 1。
record 最长 30 秒、99 Hz；Trace 单次最长 10 秒。任一预算耗尽即停止，不能静默新建会话。
每次成功的 stat、record 或 Trace 都必须把 Broker 已验证的原始证据字节数带入优化会话，用
实际正数字节替换预留上限，不能把已经产生的证据静默记为 0。

## 匹配 A/B 与 Verified Improvement

A/B 不变量包括基础 digest、Builder/网络身份、Dockerfile 固定配方、target/platform/build args、
命令、资源、Benchmark 合同、Collector 策略、内核、perf 版本和实际事件来源。Treatment 包括
mutable 路径哈希、可执行文件哈希/Build ID 和候选最终镜像 digest。同一授权 Recipe 产生不同
最终 digest 是正常候选变化，不终止会话。

只有正确性通过、Benchmark 目标和参数一致、环境与事件来源一致、达到配置阈值、性能证据支持
假设、没有不可接受的 CPU/内存/I/O/节流转移，并通过哈希、守恒和确定性重放验证，才能输出
Verified Improvement。partial、缺失 Benchmark、正确性失败或任一不变量不匹配只能给候选结论。

最终报告必须列出 Iteration 实际绑定的 Profile Comparison、Benchmark Comparison 和通用容器
Comparison ID；单独调用产生的 Comparison 只能作为旁证，不能冒充最终 Iteration 输入。Profile
少于 100 条逻辑记录只是噪声提示，不是单独的可比性硬失败；报告必须公开真正决定结论的质量状态
与 metadata differences。

`verified_improvement` 可直接完成 `retain_candidate`。对于 `candidate_improvement`、
`candidate_regression`、`no_material_change` 或 `not_comparable`，Agent 必须先展示精确证据限制，
再询问一次用户要“保留未验证候选”还是“恢复基线”。保留需要一次新的明确确认，并生成内容绑定的
`DockerOptimizationDispositionArtifact`；原 Iteration 结论保持权威，报告只能称为“用户选择保留
的未验证候选”。恢复则要求工作区回到候选前的精确字节。finalizer 会复核所选 mutable manifest、
撤销 Session 并清理已验证的临时资源；它自身不修改源码，也不会把人工选择升级为 Verified
Improvement。

短生命周期容器如果在最终 cgroup 读取前退出，只能保留最后一次已验证周期快照，并标记为 partial
下界；这不能证明不存在 CPU、内存、I/O 或节流转移，也不能为了得到 verified 结论而放宽。报告
默认输出在聊天中；在 `mutable_paths` 之外创建项目报告文件需要另行授权。

## 实施与发布门禁

实施拆成独立审查提交：版本/配置合同；构建 Artifact 与快照；Build Adapter；会话/MCP；匹配
A/B 与 Agent 集成；最终包、宿主机与 Docker 验收。每阶段必须先通过正常、拒绝、边界、lint、
类型、Schema 及相关 Python/Rust 协议测试，才能进入下一阶段。

本地候选已经通过 Python 3.12/3.13、85% 覆盖率门禁、可复现 wheel/sdist 与 DEB、包冒烟、
Schema/协议，以及 Rust fmt、Clippy、测试、audit、deny 门禁。2026-08-26 源码审查发现的
问题已经修复并补充拒绝路径回归测试。稳定发布仍需完成已安装主机
的不自动激活/升级/回滚/卸载验收、v0.3.1 宿主机与固定 Docker 回归，以及真实
rootless/rootful Docker 验收。优化会话和本实施合同都不会创建 v0.3.2 Tag。
