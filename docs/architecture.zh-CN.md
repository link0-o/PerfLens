# PerfLens 架构说明

简体中文 | [English](architecture.md)

```text
CLI / MCP 边界
 ↓
Application Service ─→ Contract 映射 ─→ 有界产物写入器
 ↓
ProfileAdapter/ProfileStream ─→ 轻量领域聚合
Benchmark/Metric Adapter       ─→ 确定性比较
Symbol Provider                ─→ 已验证的源码定位
手工采集服务                   ─→ 有界命令执行器 ─→ 系统 perf
普通用户项目启动器 ─→ 新 PID ─┐
自动 PID 计划 ─→ Unix Socket ─→ 受限 Collector ─→ 固定 spool
管理员显式部署 ─→ 版本化 TOML ─→ perflens-admin ─→ systemd
```

## Core 与边界层

领域层使用冻结且带 `slots` 的轻量记录、整数 Frame ID 和标准库 Protocol。它不导入 Pydantic 或 Typer，因此 Profile 解析和聚合热路径不会依赖 CLI 或边界验证框架。

格式 Adapter 负责流式解析和 Frame Table；Application Service 负责生命周期、指纹、元数据和向带版本 Contract 的转换；CLI 与 MCP 只负责参数、权限和输出边界。

输入被视为不可变数据。普通分析永远不能覆盖源 Profile。产物先写入同目录临时文件，完成序列化和 `fsync` 后再原子发布。主动采集只能发布到不存在的新路径。

## Profile 输入

- folded 与 `perf script` 使用流式文本解析器；
- `perf.data` 不由 PerfLens 直接解析，而是交给系统 `perf script` 转换；
- 外部命令不经过 shell，并限制可执行文件、超时、stdout、stderr 和生成文件大小；
- 错误记录的预览、警告数量、记录数、行长、栈深和唯一对象数量都有上限。

这使 PerfLens 能保持确定性，同时把 Linux 工具版本兼容问题留在明确的 Adapter 边界。

## 符号和源码定位

`pyelftools` 只检查 ELF 身份、Build ID、Debug Link 和调试能力，不承担自研高吞吐 DWARF 符号化。

源码符号化由按模块复用的 `llvm-symbolizer` 或 `addr2line` 进程完成。查询会分批发送，缓存键包含 Build ID、模块相对偏移和 Resolver 版本。PerfLens 只接受已经验证的模块相对偏移，不会在缺少映射信息时根据运行时地址猜测 PIE/ASLR 基址。

源码上下文读取必须位于允许的 workspace 内，并限制文件大小、上下文行数和单行字符数。

## 证据和结论

规则引擎与 Evidence Builder 都是确定性的。符号/DSO 规则最多产生 L1/L2 的 `candidate`（候选）分类，不能产生“已确认根因”。

L4 `Verified Improvement` 必须来自后续、工作负载可比且保持正确性的 A/B 验证。Profile 百分比变化只表示事件分布，不能代替绝对时间和 Benchmark。

## MCP 与 Skill

MCP Server 和仓库 Skill 是两条独立的编排边界：

- MCP 把 Core 暴露为本地、有类型、可分页的工具；
- Skill 约束 Agent 如何收集和解释证据；
- 两者都不会被确定性 Core 导入，也不会调用 LLM API。

MCP 在服务端分别控制允许根目录、产物写入、进程执行、主动采集和 PID 附加。不能只依赖客户端提示词保证权限。

## 主动采集

主动采集和只读 Adapter 完全分离，并且默认关闭。只有服务器策略、调用级精确授权和目标约束全部通过后，才会执行一个明确命令或附加一个 PID。

采集器只运行绝对可执行文件，不调用 shell 或 sudo；运行过程中监控输出大小；超时或超限时终止整个子进程组；最后以不覆盖方式发布新产物。

`perf stat` 输出由独立 Metric Adapter 处理，不混入栈 ProfileAdapter 层级。

自动采集采用不同的权限边界：MCP 生成短期、单次、绑定 PID 所有者和启动时间的计划；可选 Collector 通过 Unix Socket 对等凭据和独立只读策略再次校验，只接受 PID，且只能写固定 spool。Collector 还会在启动 perf 前检查累计字节、文件数和文件系统空闲余量，不足时拒绝新采集且不删除旧证据。Collector 不接受 shell、任意命令、任意输出路径或全系统目标。MCP 与 Skill 始终保持普通用户权限。

当前项目自动优化时，普通用户启动器可以在用户确认后启动一个项目内可执行文件，
内部取得新 PID，再走同一条 PID 计划链路。Collector 不会收到或启动项目命令。
`perflens-admin` 只由管理员显式调用，读取版本化、数据化的 Collector TOML；MCP、
Skill 和 Agent 不会调用 sudo 或部署系统服务。

Collector 协议只有两类有界请求：唯一会产生系统状态的 `collect_pid` 必须携带短期、
单次、绑定 PID/UID/启动时间的计划；`health` 只返回版本化就绪元数据，不执行 perf、
不消费计划、不写 spool。服务端校验调用方 peer UID，客户端通过内核 `SO_PEERCRED`
复核响应 PID/UID，管理员部署还要求专用 `perflens` 服务 UID。部署和升级必须完成
`health` 往返，不能把遗留 Socket 文件或错误身份进程当成服务就绪。

`perflens status` 是独立的只读诊断边界。它检查项目引导、Skill、MCP 配置片段、
Collector 资产、Socket、当前登录会话用户组和主机 perf 条件，但不会采样、连接目标
进程或宣称真实 Collector 已经通过验收。配置和访问前置条件满足后，它会额外执行一次
最长 500 毫秒的 `health` 往返；只有专用服务 UID 与内核 `SO_PEERCRED` 身份都通过，
才会显示 `ready_for_verification`。

原生 Debian 发行同样按权限拆包：`perflens` 主包只暴露普通用户 CLI/MCP，
`perflens-collector` 包才增加管理员和 Collector 入口。两个包的安装过程都不会部署
或启动服务；特权状态只能由管理员随后显式创建，也只能通过验证托管标记的
`perflens-admin undeploy` 移除。

Debian 的多个命令入口可以共享私有运行时启动器，但 Codex 配置和 systemd 必须保留
经过验证的 `/usr/bin/perflens-mcp` 与 `/usr/bin/perflens-collector` 入口名，启动器才能
确定要进入 MCP 或 Collector。只有父目录与解析目标满足相应所有者和不可写检查时，
引导与部署器才会保留符号链接路径。

## 依赖方向

```text
CLI / MCP / Pydantic Contract
            ↓
     Application Service
            ↓
Domain + Adapter + Aggregation
```

下层不能反向依赖上层。新增能力时，应先实现可测试的确定性服务，再由 CLI/MCP 调用，而不是把业务逻辑直接写进命令或 MCP Handler。
