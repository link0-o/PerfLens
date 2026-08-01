# PerfLens 发布就绪检查

简体中文 | [English](release-readiness.md)

本文把最终实现与项目 Definition of Done 对应起来。表中的本地验证在 2026-08-01 完成；工作流配置本身不等于远程 GitHub Actions 已经成功运行。

## 功能范围

里程碑 0～9 已实现：

- folded、`perf script` 和经系统 perf 转换的 `perf.data` 分析；
- 精确 Self/Inclusive 热点和调用路径；
- ELF/调试信息检查与源码符号化 Provider；
- 只产生候选结论的证据规则和 JSON/Markdown 报告；
- 带类型、分页和权限控制的 MCP Server；
- PerfLens Performance Analysis Skill；
- Profile/Benchmark 比较及常见 Benchmark JSON Adapter；
- 默认关闭、必须明确授权的主动采集。

项目仍然明确不包含：LLM API、自研 Agent 循环、Web UI、自动修改源码、Benchmark 执行器、生产监控、直接解析 `perf.data` 二进制以及面向特定应用的规则。

## 质量门禁

| 检查项 | 命令或证据 | 当前结果 |
|---|---|---|
| 代码规范 | `ruff check .` | 通过 |
| 严格类型 | `pyright` | 0 错误、0 警告 |
| Python 3.12 | `pytest -q`，Python 3.12.13 | 111 通过 |
| Python 3.13 | 隔离环境 `pytest -q` | 111 通过 |
| 覆盖率 | `pytest --cov=perflens --cov-fail-under=85` | 85.09%，通过 |
| Skill | Skill 结构和打包测试 | 通过 |
| Schema | 已提交 Schema 与 Contract 生成结果相等 | 通过 |
| 依赖锁 | `uv export --locked` | 通过 |
| 漏洞扫描 | 对完全锁定运行依赖执行 `pip-audit` | 未发现已知漏洞 |
| SBOM | uv CycloneDX 1.5 导出 | 通过 |
| wheel/sdist | 全新临时目录构建和隔离安装 | 全部通过 |
| SHA-256 | wheel、sdist、Skill、SBOM | 四项全部通过 |
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

## 结论边界

- 规则匹配不是已确认根因；
- Profile 百分比变化不是绝对耗时变化；
- Benchmark 只有在环境和工作负载可比、保持正确性并重复验证后，才能支持更强结论；
- off-CPU 采集只提供 `sched:sched_switch` 栈证据，尚不能单独确认带持续时间的阻塞等待。

## 发布操作

正式发布前仍需执行[《发布流程》](releasing.zh-CN.md)中的版本同步、CHANGELOG、完整测试、构建、SBOM、校验和和标签步骤。

已经发布的 `v0.1.0` 不应移动或覆盖。本次 `Unreleased` 修复若要发布，建议使用新的补丁版本，例如 `v0.1.1`。
