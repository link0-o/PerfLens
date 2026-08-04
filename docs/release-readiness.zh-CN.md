# PerfLens 发布就绪检查

简体中文 | [English](release-readiness.md)

本文把最终实现与项目 Definition of Done 对应起来。表中的本地验证更新到 2026-08-04；工作流配置本身不等于远程 GitHub Actions 已经成功运行。

## 功能范围

里程碑 0～10 已实现：

- folded、`perf script` 和经系统 perf 转换的 `perf.data` 分析；
- 精确 Self/Inclusive 热点和调用路径；
- ELF/调试信息检查与源码符号化 Provider；
- 只产生候选结论的证据规则和 JSON/Markdown 报告；
- 带类型、分页和权限控制的 MCP Server；
- PerfLens Performance Analysis Skill；
- Profile/Benchmark 比较及常见 Benchmark JSON Adapter；
- 默认关闭、必须明确授权的主动采集。
- 通过独立 Collector Broker 执行的、策略约束的自动 PID 采集。
- 带版本的 Collector 策略，以及不执行采集、不修改系统的运行就绪状态报告。

项目仍然明确不包含：LLM API、自研 Agent 循环、Web UI、自动修改源码、Benchmark 执行器、生产监控、直接解析 `perf.data` 二进制以及面向特定应用的规则。

## 质量门禁

| 检查项 | 命令或证据 | 当前结果 |
|---|---|---|
| 代码规范 | `ruff check .` | 通过 |
| 严格类型 | `pyright` | 0 错误、0 警告 |
| Python 3.12 | `pytest -q`，Python 3.12.13 | 239 通过 |
| Python 3.13 | 隔离环境 `pytest -q` | 239 通过 |
| 覆盖率 | `pytest --cov=perflens --cov-fail-under=85` | 85.47%，通过 |
| Skill | Skill 结构和打包测试 | 通过 |
| Schema | 已提交 Schema 与 Contract 生成结果相等 | 通过 |
| 依赖锁 | `uv export --locked` | 通过 |
| 漏洞扫描 | 对完全锁定运行依赖执行 `pip-audit` | 未发现已知漏洞 |
| SBOM | uv CycloneDX 1.5 导出 | 通过 |
| wheel/sdist | 全新临时目录构建和隔离安装 | 全部通过 |
| SHA-256 | wheel、sdist、两个 DEB、Skill、SBOM | 六项全部通过 |
| Collector 健康协议 | 双向内核 peer 凭据 → 只读 `health` → 版本化就绪结果 | 授权、错误服务 UID、拒绝、遗留 Socket 超时及部署等待路径通过 |
| 部署验收命令 | `accept-collector` → 内置负载 → 授权 stat 计划 → Broker | 可执行 perf Test Double 通过 |
| Collector 存储边界 | 累计字节/文件数/空闲余量 → 启动 perf 前预留 | 三类拒绝及 Unix Socket 端到端通过 |
| Collector 存储检查 | `spool-status` → 直接普通文件 → 配额/磁盘余量 | 中文摘要、版本化 JSON 和异常项拒绝通过 |
| Collector 用户隔离 | 单实例单 UID；策略/资产/部署拒绝多 UID | 拒绝路径和组可读边界已验证 |
| 项目工作负载 | 普通用户启动 → 内部 PID → Broker → 清理 | 可执行 perf Test Double 端到端通过 |
| 管理员部署 | 严格 TOML → 内置资产 → 固定命令 → Socket | 成功、回滚和拒绝路径通过 |
| 管理员升级 | 固定已部署策略 → unit 哈希比较 → 安全替换/重启 → 失败恢复 | 保留策略/证据、同版重启、更新、恢复和拒绝路径通过 |
| 策略安全更新 | 独立候选 → 严格验证 → 原子替换/重启/健康检查 → 失败恢复 | UID/spool 固定、注释保留、只读预检和拒绝路径通过 |
| 管理员撤销部署 | 托管标记/所有者/权限 → 固定停用 → inode 复核 → 删除 unit | 保留数据和拒绝路径通过 |
| 原生 DEB | Debian 13 主包与 Collector 拆包 | 提取命令冒烟和逐字节重复构建通过 |
| 性能 | 可复现 small/medium/large folded 语料 | 已记录基线 |

覆盖率目前只比 85% 门槛高少量余量。后续新增代码应优先补齐安全错误分支测试，而不是降低门槛。

## 兼容性证据

- Linux：Debian 13、x86_64；
- Python：3.12.13 和 3.13；
- perf：本机 6.12.90，只读语法和 Provider 流程通过；
- GNU addr2line：针对 PIE、共享库、Strip 和独立调试文件夹具验证；
- LLVM symbolizer：本机未安装，JSON 协议和长驻进程生命周期通过 Test Double 验证；
- MCP：使用官方 Python SDK 2.x 完成客户端/服务端端到端测试。

完整兼容范围见 `docs/compatibility.md`。遇到跨主机 `perf.data` 时，仍可能需要匹配的 perf、DSO、Build ID、调试文件和挂载命名空间数据。

## 安全验证

- 路径穿越和符号链接逃逸会被拒绝；
- 输入 Profile 不会被覆盖；
- 外部工具不经过 shell，启动、超时、输出洪泛和写入失败均有稳定错误；
- 超长单行、增长中的文件、Benchmark/产物读取和源码上下文保持有界；
- 非有限 Benchmark 与 perf-stat 数值会被拒绝；
- 大批量符号地址分组发送，避免标准输入/输出管道死锁；
- 主动采集默认关闭，PID 附加具有额外独立权限门。
- 自动计划绑定 PID 所有者和启动时间，短期且单次；Collector 验证 Unix 对等 UID、独立策略和固定 spool，并在启动 perf 前执行累计字节、文件数和磁盘空闲余量配额。
- 项目可执行程序始终由普通用户启动，Collector 只收到 PID 计划；管理员部署配置按
  不跟随符号链接的单次快照读取，系统命令使用固定绝对路径白名单。

## 结论边界

- 规则匹配不是已确认根因；
- Profile 百分比变化不是绝对耗时变化；
- Benchmark 只有在环境和工作负载可比、保持正确性并重复验证后，才能支持更强结论；
- off-CPU 采集只提供 `sched:sched_switch` 栈证据，尚不能单独确认带持续时间的阻塞等待。

## 发布操作

正式发布前仍需执行[《发布流程》](releasing.zh-CN.md)中的版本同步、CHANGELOG、完整测试、构建、SBOM、校验和和标签步骤。

已经发布的 `v0.1.0` 不应移动或覆盖。当前候选版本已经提升为 `v0.1.1`；提交并推送
发布提交后，应创建新的 `v0.1.1` 标签。
