# PerfLens 发布就绪检查

简体中文 | [English](release-readiness.md)

本文是 2026-08-23 对 v0.3.1 发布候选的本地验证记录，不代替 Tag 工作流，也不代替每台
部署主机的真实验收。每次发布都必须重新执行[《发布流程》](releasing.zh-CN.md)；远程工作流
已经配置不等于对应运行已经通过。

## 候选范围

v0.3.0 的 Linux 宿主机 `stat/record/sched/off_cpu/lock` 路径继续受支持。v0.3.1 新增本地
Linux Docker Engine、cgroup v2 下的一个明确进程：

- 已有容器的有界发现与身份绑定；
- 使用包内 Container Gate 的固定策略托管临时容器；
- `per_run` 与连接级、仅内存保存的 `bounded_session` 授权；
- 与容器身份绑定的 `stat/record` 和 `full_diagnostics` trace 计划；
- cgroup v2 资源上下文、模块/Build ID/源码映射和 PMU 降级来源；
- 与证据绑定的 Benchmark、处理变量、正确性和匹配 A/B 验证；
- 通过 `perflens init --docker` 提供项目级 Codex/Claude Code Skill 与 MCP 集成。

本版本不包含远程 Docker、Docker Desktop VM、Compose/Kubernetes、镜像 build/pull、任意
Docker 参数、整容器 perf 聚合，也不包含计划进入 v0.4.0 的 C/C++、Java、Python、Go
运行时锁 Adapter。

## 自动化本地门禁

| 门禁 | 2026-08-23 候选结果 |
|---|---|
| Ruff | 通过 |
| Pyright 严格模式 | 0 错误、0 警告 |
| Python 3.12 | 1069 通过；覆盖率 85.15% |
| Python 3.13 | 1069 通过；覆盖率 85.15% |
| Rust 格式/Clippy/测试 | 通过；64 个测试 |
| Rust 依赖 | 使用官方本地 advisory DB 干净克隆运行 `cargo audit` 无发现；`cargo deny check` 通过 |
| 协议/Schema | 生成文件无差异；Python/Rust 有效与无效 golden 通过 |
| Python 包 | wheel 与 sdist 可复现构建，并通过隔离安装冒烟 |
| Debian 包 | 两个可复现 `0.3.1-7` amd64 DEB 通过提取/包冒烟；不激活服务或 Docker |

具体数量只描述本次候选检出，测试增加后会变化。覆盖率门槛保持 85%，不得为了发布降低。

## 安全与解释门禁

- Docker、Agent、Skill、MCP、Broker 和 Helper 边界保持分离；任何组件都不调用 sudo，也不
  修改 sysctl、Docker 用户组、daemon 配置或 Socket 权限。
- Docker 命令及挂载/网络/资源策略从类型化项目合同派生；远程 endpoint、任意参数、
  build/pull、privileged、host PID、设备、额外 capability、Docker Socket 挂载和宿主路径
  逃逸都会被拒绝。
- Broker、stat/record Helper 与 Trace Helper 独立验证容器目标 UID、PID 启动时间、
  namespace、cgroup、计划期限、单次身份和资源上限。
- 公开输出不保存完整 inspect、环境变量、标签、Socket/挂载源/cgroup 路径和目标外 argv；
  缺失的符号/源码证据保持 `partial`。
- cgroup 差值属于整容器上下文，不是目标进程独占证据；软件 PMU 降级不能支持 IPC、
  cache-miss、branch-miss 或微架构结论。
- `Verified Improvement` 要求处理变量确实变化、环境指纹相同、容器绑定的正确性与
  Benchmark 成功、绝对指标改善、确定性重放通过且未观察到资源转移。

## 剩余真实主机发布门

自动化测试使用真实 Unix Socket 和有界 Docker/perf Test Double。候选仍需在本机执行一次
显式安装验收，覆盖实际可用的 rootless/rootful Docker、已有容器、托管临时容器、软件
PMU 降级和宿主 Collector 回归。rootful UID 0 还要求专用管理员风险确认。结果只证明该
主机和对应 workload。

在真实验收、最终安装包重建、干净工作区检查和远程 CI 全部通过前，不要创建或推送
`v0.3.1`。已有 `v0.3.0` Tag 保持不可变。
