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
显式采集服务                   ─→ 有界命令执行器 ─→ 系统 perf
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

## 依赖方向

```text
CLI / MCP / Pydantic Contract
            ↓
     Application Service
            ↓
Domain + Adapter + Aggregation
```

下层不能反向依赖上层。新增能力时，应先实现可测试的确定性服务，再由 CLI/MCP 调用，而不是把业务逻辑直接写进命令或 MCP Handler。
