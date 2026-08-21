# PerfLens 发布就绪检查

简体中文 | [English](release-readiness.md)

本文是 2026-08-15 对 0.2.0 修复线的验证快照，不是永久不变的宣传页。下一次正式发布
必须重新执行[《发布流程》](releasing.zh-CN.md)中的全部门禁；工作流存在不等于对应远程
GitHub Actions 已经成功。

## 当前可发布范围

当前稳定闭环包括：

- folded、`perf script` 和经系统 perf 转换的 `perf.data` 分析；
- 带守恒与来源绑定的热点、调用路径、源码归因和 JSON/Markdown 证据；
- Profile/Benchmark 比较，以及同工作负载、同事件来源、保持正确性的 A/B 验证；
- 带类型、分页、权限开关和证据完整性校验的 MCP Server；
- Codex/Claude Code 项目 Skill；
- 默认关闭、明确授权、只接受 PID 的 Collector 自动采集；
- `cap_perfmon` 与可选 `paranoid3_helper` 两种部署模式；
- 正式支持的 `stat`、`record`，以及硬件 PMU 不可用时可审计的软件事件降级；
- Collector 部署、升级、策略更新、撤销、spool 检查、归档和显式清理。

`sched`、`lock`、`off_cpu` **不在当前稳定发布声明中**。它们只在 `cap_perfmon`
Broker 中保留默认关闭的原始实验入口，没有专用确定性分析器；`paranoid3_helper` 明确
拒绝它们。下一功能版本候选为 `v0.3.0`，范围与门禁见
[采集能力扩展路线图](collector-capability-roadmap.zh-CN.md)。

项目仍然不包含：LLM API、自研 Agent 循环、Web UI、任意源码自动修改、通用 Benchmark
执行平台、生产 APM、直接解析 `perf.data` 二进制、内存泄漏分析、GPU 分析、分布式链路
追踪以及面向某个应用的专用规则。

## 最近一次本地门禁快照

| 检查项 | 命令或证据 | 2026-08-15 快照 |
|---|---|---|
| 代码规范 | `ruff check .` | 通过 |
| 严格类型 | `pyright` | 0 错误、0 警告 |
| Python 完整测试 | `pytest -q`（当前开发环境） | 554 通过 |
| 覆盖率 | `pytest --cov=perflens --cov-fail-under=85` | 85.48%，通过 |
| Python CI 矩阵 | `.github/workflows/ci.yml` | 配置 Python 3.12、3.13；发布时以对应远程运行结果为准 |
| Rust 格式/静态检查 | 固定工具链 `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings` | 通过 |
| Rust 测试 | `cargo test --locked` | 25 个库测试和 2 个二进制测试通过 |
| Schema/协议 | 已提交 Schema、跨语言有效/无效 golden、未知字段拒绝 | 通过 |
| Skill | 结构、打包和工作流安全测试 | 通过 |
| wheel/sdist | 重复构建、逐字节比较、隔离安装 | 通过 |
| 原生 DEB | Debian 13 主包/Collector 拆包、重复构建、提取/安装冒烟 | 通过 |
| 依赖与供应链 | 锁文件、许可证/漏洞检查、SBOM、Action 固定、发布来源证明配置 | 通过本地门禁；远程证明需由标签工作流产生 |

这些数字属于一次快照。测试增加后，文档不应继续复制旧数量；发布记录应保存实际命令、
提交 SHA、Python/Rust 版本和完整日志。覆盖率门槛仍是 85%，不得为了新增功能而降低。

## Collector 与真实主机证据

自动化测试覆盖真实 Unix Socket、对等身份、PID 复用/跨 UID/重放/过期拒绝、固定 spool、
容量配额、产物哈希与权限、部署/升级/回滚/撤销，以及 Python/Rust 私有协议的拒绝路径。
成功和失败的 perf 路径使用受控可执行 Test Double，避免把 CI 主机权限误当成产品能力。

此外，Debian 13 人工验收已经证明：

- `paranoid3_helper` 与非特权 Broker 可以完成认证握手；
- 在 VMware 硬件 PMU 没有产生可用计数时，可以完成软件 `stat`；
- `cpu-clock record` 和调用栈采样可以完成；
- Collection 会报告 `actual_event_source=software`、降级原因与 IPC/cache/branch 限制；
- 原始证据哈希、Collection、分析输入、转换清单、热点/调用路径权重守恒可以验证。

这只证明该主机和该短时工作负载。它不证明硬件 PMU、其他内核/虚拟机/LSM、其他 PID
或实验 trace 模式一定可用。每台主机仍要由普通授权用户运行：

```bash
perflens accept-collector --authorize-host-acceptance
```

## 安全与解释门禁

- 不经过 shell；用户路径必须规范化并拒绝符号链接逃逸；源 Profile 永不覆盖；
- MCP、Skill、Agent 和 Python Broker 不运行 sudo，也不持有 Helper 权限；
- 用户工作负载始终由普通用户启动，Collector/Helper 只接收短期、单次、同 UID 的 PID 计划；
- `paranoid3_helper` 只执行固定 root 所有 perf 路径，只允许 `stat`、`record`；
- 原始输入、转换结果、最终分析和 Agent 可见分页必须保持来源绑定与哈希一致；
- 解析警告、未知帧、丢失事件、截断和未解析权重必须保留，不能伪装成零；
- 规则匹配不是根因，Profile 百分比不是绝对耗时，软件事件不能支持 IPC/cache/branch 结论；
- 只有匹配工作负载、相同事件来源、正确性通过并重复测量的 A/B，才能称为已验证改进。

## 标签与下一版本

本历史快照生成时源码版本仍为 `0.2.0`。当前发布元数据已更新为 `0.3.0`；每次尝试创建
`v0.3.0` 标签都必须重新运行发布工作流中的完整门禁，不能把这份旧快照当成通过证据。

已经对外发布的标签应保持不可变。即使确认旧标签/Release 从未提供给用户，删除并重建也
只能作为单独审查的仓库恢复操作；[发布流程](releasing.zh-CN.md)不把覆盖标签作为正常
步骤，默认做法仍是修复后发布新版本。
