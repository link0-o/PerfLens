# PerfLens 兼容范围

简体中文 | [English](compatibility.md)

| 组件 | 支持范围 |
|---|---|
| Python | 3.12 和 3.13 |
| 操作系统 | 以 Linux 为主要目标；要求兼容 POSIX 的文件语义 |
| 架构 | x86_64；有 CI 资源时测试 aarch64 |
| 输入 | FlameGraph folded 栈；受支持的 `perf script` 文本；由系统 perf 转换的 `perf.data`；PerfLens、pyperf、Google Benchmark 和 hyperfine JSON |
| perf | 支持 `script --ns -F` 的 Linux perf；测试与人工验收覆盖 perf 6.12.x，跨版本 Profile 仍应优先使用与采集端匹配的 perf |
| ELF/DWARF | 使用 pyelftools 0.33 读取 ELF；使用 LLVM JSON Provider 或 GNU/elfutils addr2line 作为源码定位后备 |
| 规则 | 安全 YAML；安装包内置通用、Linux 和 C++ 候选规则 |
| 报告 | JSON 证据包和 Markdown |
| MCP | 官方 Python SDK 2.x，本地 stdio 传输 |
| Skill | Codex `.agents/skills` 与 Claude Code `.claude/skills` 项目 Skill，并使用 `skill-creator` 验证 |
| AI 客户端配置 | Codex 项目 `.codex/config.toml`；Claude Code 项目 `.mcp.json` |
| 主动采集 | `record`、`stat` 是正式能力；`cap_perfmon` 中的 `sched`、`lock`、`off_cpu` 只是默认关闭的原始实验入口，尚无专用确定性分析器 |
| 自动采集 | 普通用户项目启动器，加上只接受 PID 的 Linux Collector Broker；使用 `SO_PEERCRED`，并提供 systemd 模板 |
| Collector 策略 | 当前版本 1，生成策略默认只允许 `record`、`stat`；缺失版本号按旧版版本 1 读取，不支持的版本会被拒绝 |
| paranoid=3 Helper | 仅支持 `record`、`stat`；`sched`、`lock`、`off_cpu` 会由协议或策略明确拒绝 |
| 原生 DEB | Debian 13 `amd64`、系统 Python 3.13；主包和完全同版本 Collector 包分离 |
| 产物 Schema | 1.0 |

PerfLens 不直接解析 `perf.data`。二进制兼容性由选定的系统 `perf` 负责；无法解码
Profile 时，应使用与采集环境匹配的 perf。GNU addr2line 后备流程已使用 Binutils 2.44
验证。由于开发主机没有安装 `llvm-symbolizer`，LLVM JSON Provider 目前通过协议 Test
Double 验证。MCP 行为使用官方 SDK 客户端在内存中完成测试。

Collector Broker 已使用真实 Unix Socket 和可执行 perf Test Double 完成端到端测试。
Debian 13 人工主机验收还证明了 `paranoid3_helper` 可以在硬件 PMU 没有产生可用计数时，
完成软件 `stat` 与 `cpu-clock record` 的短时采集。该验收不代表所有内核、虚拟机、PMU、
LSM 或高级 trace 模式都兼容；`sched`、`lock`、`off_cpu` 尚无真实主机稳定性声明。

运行下面的命令，可以只读汇总引导文件、Skill、生成的 MCP 配置、Collector 资产、
Socket 访问、用户组成员关系和主机 perf 能力：

```bash
perflens status --project /项目的绝对路径
```

状态为“就绪”只代表可以进行一次明确授权的真实探测；只有
`perflens accept-collector --authorize-host-acceptance` 成功，才证明当前主机的短时
`stat`/`record` 路径已通过验收，且结论仍受返回的事件来源与证据限制约束。
