# PerfLens 发布就绪检查

简体中文 | [English](release-readiness.md)

本文是 2026-08-26 对发布版 v0.3.2 的验证记录，不代替远程 Tag 工作流，也不代替每台
部署主机的真实验收。每次发布都必须重新执行[《发布流程》](releasing.zh-CN.md)；远程工作流
已经配置不等于对应运行已经通过。

## 发布范围

v0.3.0 的 Linux 宿主机 `stat/record/sched/off_cpu/lock` 与 v0.3.1 固定镜像 Docker 路径
继续受支持。v0.3.2 新增默认关闭的 `bounded_optimization_session`：

- 一次经审阅的授权会绑定客户端连接、Recipe、不可变上下文、mutable 路径、Benchmark
  合同、Collector 策略、Builder/网络身份和硬预算；
- baseline 与最多三个 candidate 使用私有、内容寻址的上下文快照构建；
- Agent 根据证据选择 `stat`、`record` 或可用 Trace 模式，不机械运行全部模式；
- Build Artifact、workload 证据、正确性/Benchmark、资源上下文、Treatment 与确定性重放
  绑定成匹配 A/B iteration；
- preview 不 build/pull，会话不授权任意 Docker 参数、路径、commit、push、Tag 或 Release。

兼容的 v0.3.1 目标运行时覆盖本地 Linux Docker Engine、cgroup v2 下的一个明确进程：

- 已有容器的有界发现与身份绑定；
- 使用包内 Container Gate 的固定策略托管临时容器；
- `per_run` 与连接级、仅内存保存的 `bounded_session` 授权；
- 与容器身份绑定的 `stat/record` 和 `full_diagnostics` trace 计划；
- cgroup v2 资源上下文、模块/Build ID/源码映射和 PMU 降级来源；
- 与证据绑定的 Benchmark、处理变量、正确性和匹配 A/B 验证；
- 通过 `perflens init --docker` 和显式客户端选择提供项目级 Codex、Claude Code、OpenCode
  与本地 Copilot Skill/MCP 集成。

本版本不包含远程 Docker、Docker Desktop VM、Compose/Kubernetes、任意 Docker 参数、
整容器 perf 聚合，也不包含计划进入 v0.4.0 的 C/C++、Java、Python、Go 运行时锁 Adapter。
优化构建只能通过类型化本地 Build Adapter 和三种明确网络层级之一执行。

## 自动化本地门禁

| 门禁 | 2026-08-26 发布结果 |
|---|---|
| Ruff | 通过 |
| Pyright 严格模式 | 0 错误、0 警告 |
| Python 3.12 | 1324 通过；覆盖率 85.19% |
| Python 3.13 | 1324 通过；覆盖率 85.19% |
| Rust 格式/Clippy/测试 | 通过 |
| Rust 依赖 | 使用官方本地 advisory DB 干净克隆运行 `cargo audit` 无发现；`cargo deny check` 通过 |
| 协议/Schema | 生成文件无差异；Python/Rust 有效与无效 golden 通过 |
| Python 包 | wheel 与 sdist 可复现构建，并通过隔离安装冒烟 |
| Debian 包 | 两个可复现 `0.3.2-1` amd64 DEB 通过提取/包冒烟；不激活服务或 Docker |
| Python 依赖 | 锁定运行时导出通过 `pip-audit --no-deps --disable-pip --strict`；已生成 CycloneDX 1.5 SBOM |

具体数量只描述本次 Tag 检出，测试增加后会变化。覆盖率门槛保持 85%，不得为了发布降低。

## 安全与解释门禁

- Docker、Agent、Skill、MCP、Broker 和 Helper 边界保持分离；任何组件都不调用 sudo，也不
  修改 sysctl、Docker 用户组、daemon 配置或 Socket 权限。
- Docker 命令及挂载/网络/资源策略从类型化项目合同派生；远程 endpoint、任意参数、
  未绑定合同的 build/pull、privileged、host PID、设备、额外 capability、Docker Socket 挂载和宿主路径
  逃逸都会被拒绝。
- 离线构建层会拒绝除 `none` 外的所有显式 `RUN --network` 值；管理员固定联网层只允许
  `none` 或 `default`。
- Preview/Session 到期具有有界清理定时器和交互时回收；MCP 断开时撤销活动优化授权，并
  保守释放经过身份核验的资源。
- Broker、stat/record Helper 与 Trace Helper 独立验证容器目标 UID、PID 启动时间、
  namespace、cgroup、计划期限、单次身份和资源上限。
- 公开输出不保存完整 inspect、环境变量、标签、Socket/挂载源/cgroup 路径和目标外 argv；
  缺失的符号/源码证据保持 `partial`。
- cgroup 差值属于整容器上下文，不是目标进程独占证据；软件 PMU 降级不能支持 IPC、
  cache-miss、branch-miss 或微架构结论。
- `Verified Improvement` 要求处理变量确实变化、环境指纹相同、容器绑定的正确性与
  Benchmark 成功、绝对指标改善、确定性重放通过且未观察到资源转移。

## 真实主机验收与剩余兼容边界

自动化测试使用真实 Unix Socket 和有界 Docker/perf Test Double。2026-08-26 已在一台安装后
rootful Docker 主机上，以非 root workload 完成 v0.3.2 有界优化全链路：Preview 与一次
授权、baseline/candidate 构建、正确性和 7 次 Benchmark、两侧软件事件 `stat`/`record`、
确定性比较，以及经过身份复核的容器清理。Benchmark 与绝对 CPU 时间明显分离，固定环境和
实际事件来源一致，确定性重放通过；但两侧 Profile 的未解析符号质量为 partial，短生命周期
容器的 cgroup 资源差值也只是下界，因此 Iteration 正确保持为 `not_comparable`。这是预期的
保守门禁，不是 Verified Improvement 声明。

该验收只证明所测试的 rootful daemon、非 root workload、内核、perf、Builder 与项目合同。
rootless Docker、管理员显式开放的 UID 0、其他 Builder 和主机组合仍需分别验收。包不自动
激活及升级/回滚/卸载已有包和事务测试覆盖，管理员仍应在自己的部署主机上复核。

只应从干净且通过验证的发布提交创建本地 annotated Tag；该提交进入 `origin/main` 且分支 CI
通过后才能推送 Tag，随后由 Tag 触发的 Release 工作流再次执行全部门禁。已有 `v0.3.0` 与
`v0.3.1` Tag 保持不可变。
