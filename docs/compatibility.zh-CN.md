# PerfLens 兼容范围

简体中文 | [English](compatibility.md)

| 组件 | 支持范围 |
|---|---|
| Python | 3.12 和 3.13 |
| 操作系统 | 以 Linux 为主要目标；要求兼容 POSIX 的文件语义 |
| 架构 | x86_64；有 CI 资源时测试 aarch64 |
| 输入 | FlameGraph folded 栈；受支持的 `perf script` 文本；由系统 perf 转换的 `perf.data`；PerfLens、pyperf、Google Benchmark 和 hyperfine JSON |
| perf | 支持 `script --ns -F` 的 Linux perf；本地使用 6.12.90 测试 |
| ELF/DWARF | 使用 pyelftools 0.33 读取 ELF；使用 LLVM JSON Provider 或 GNU/elfutils addr2line 作为源码定位后备 |
| 规则 | 安全 YAML；安装包内置通用、Linux 和 C++ 候选规则 |
| 报告 | JSON 证据包和 Markdown |
| MCP | 官方 Python SDK 2.x，本地 stdio 传输 |
| Skill | 仓库 `.agents/skills` 下的 Skill，并使用 `skill-creator` 验证 |
| 主动采集 | perf record/stat/sched/lock 和基于 sched-switch 的 off-CPU 证据；默认关闭且取决于系统权限 |
| 自动采集 | 普通用户项目启动器，加上只接受 PID 的 Linux Collector Broker；使用 `SO_PEERCRED`，并提供 systemd 模板 |
| Collector 策略 | 版本 1；缺失版本号按旧版版本 1 读取，不支持的版本会被拒绝 |
| 原生 DEB | Debian 13 `amd64`、系统 Python 3.13；主包和完全同版本 Collector 包分离 |
| 产物 Schema | 1.0 |

PerfLens 不直接解析 `perf.data`。二进制兼容性由选定的系统 `perf` 负责；无法解码
Profile 时，应使用与采集环境匹配的 perf。GNU addr2line 后备流程已使用 Binutils 2.44
验证。由于开发主机没有安装 `llvm-symbolizer`，LLVM JSON Provider 目前通过协议 Test
Double 验证。MCP 行为使用官方 SDK 客户端在内存中完成测试。

Collector Broker 已使用真实 Unix Socket 和可执行 perf Test Double 完成端到端测试。
但本开发主机的 `perf_event_paranoid=3`，并且没有安装经过管理员批准的 Collector 服务，
因此尚不能证明一次真实特权采样已经成功。

运行下面的命令，可以只读汇总引导文件、Skill、生成的 MCP 配置、Collector 资产、
Socket 访问、用户组成员关系和主机 perf 能力：

```bash
perflens status --project /项目的绝对路径
```

状态为“就绪”只代表可以进行一次明确授权的真实探测，不代表真实采样已经成功验证。
