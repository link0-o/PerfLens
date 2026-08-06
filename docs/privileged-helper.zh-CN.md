# PerfLens `paranoid=3` 高权限 Helper 设计

简体中文 | [English](privileged-helper.md)

状态：`v0.2.0` 已实现并纳入原生 Debian Collector 包；正式启用仍需管理员显式选择和验收。

## 目标与非目标

目标是在 Debian `perf_event_paranoid=3` 保持不变时，通过管理员显式部署的最小高权限
组件执行受限 PID 采集。普通 CLI、MCP、Skill、分析器和公共 Collector Broker 继续使用
Python并保持普通用户权限；只有新的 Rust Helper 位于更高权限边界。

本设计不提供完整 root Python Collector，不允许 Agent/MCP 调用 sudo，不自动修改 sysctl，
不接受任意命令、环境、路径或 system-wide 目标，也不让高权限 Helper 启动用户工作负载。

## 两种部署模式

`cap_perfmon` 是默认模式，沿用受限 Collector，并要求主机策略兼容 `CAP_PERFMON`，在
Debian 上通常意味着 `perf_event_paranoid <= 2`。

`paranoid3_helper` 是管理员显式选择的高级模式。公共 Broker 不持有 capability；独立
Rust Helper 通过经过审查的 systemd 单元获得 Debian 等级 3 所需能力。安装软件包不会
自动启用该模式，配置字段和部署确认参数必须同时存在。

安装引导检测到等级 3 时提供三个结果：保持安全默认并由管理员另行审查内核策略、保持
等级 3 并部署高权限 Helper、或仅分析已有 Profile。PerfLens 只检测和解释 sysctl，不
修改它。

## 进程与身份边界

```text
Agent / Skill / MCP（普通用户）
              │ /run/perflens/collector.sock
              ▼
Python Collector Broker（无 capability）
              │ 私有、仅 Broker 可访问的 Unix Socket
              ▼
Rust privileged Helper（root UID，systemd capability bounding set）
              │ 固定 /usr/bin/perf + 固定 PID 参数
              ▼
      /var/lib/perflens-helper
```

公共 Socket 和私有 Helper Socket 使用不同目录、组和权限。Helper 必须使用
`SO_PEERCRED` 验证固定 Broker UID；知道 Socket 路径或属于普通客户端组都不能直接调用
Helper。Python Broker 也要验证 Helper 的 UID、Socket/父目录身份和每个响应 ID。

## 私有协议

请求是最大 64 KiB、带版本、严格拒绝未知字段的类型化消息。唯一有状态操作只接受：请求
ID、单次计划 ID、PID、目标 UID、PID 启动时间、枚举模式、整数毫秒时长、白名单事件、
有界频率和输出上限。协议不存在 argv、shell、环境、工作目录、perf 路径或输出路径字段。

Python/Pydantic 与 Rust/Serde 必须共享仓库中的 JSON Schema 和 valid/invalid golden
fixtures。两端都要拒绝重复/未知字段、非有限或超界数字、尾随数据、错误版本和响应 ID
不匹配。Helper 不能因为请求已经由 Python 验证就省略任何安全检查。

## 执行与产物

Helper 只执行管理员策略中固定、root 所有且不可由非 root 写入的 perf 绝对路径。参数由
枚举和白名单字段生成，使用无 shell 的进程 API。输出名称只能由计划 ID 推导并发布到
固定 spool；路径身份、软/硬链接、权限、所有者、大小、摘要、配额和文件系统空闲余量
都必须复核。

计划在启动 perf 前持久化为单次已消费状态。失败、超时、Helper/Broker 重启都不能让同一
计划再次执行。Helper 进程或 perf 子进程超时、超限时必须终止整个受控子进程并返回有界
错误，不记录 Profile、任意 stderr、目标命令或敏感路径。

## Rust 与发布边界

Rust 只用于 Helper。普通 wheel 不包含或构建 Helper，因此 Python 开发和只读分析不需要
Rust。原生 DEB 在 CI 中使用固定稳定工具链和 `Cargo.lock` 构建目标架构二进制；
最终用户不安装 Cargo 或 rustc。

Rust 代码优先使用安全抽象。不可避免的 syscall FFI `unsafe` 必须集中、写明安全前提并有
专项测试。依赖保持最少，版本锁定并进入第三方许可证清单和 Rust 供应链审计。

## 必须通过的验收

- 未授权普通用户不能连接私有 Helper；伪造 peer、响应和 Socket 替换均被拒绝；
- PID 所有者、启动时间、TTL、模式、事件、时长、频率、大小或计划重放任一不符即拒绝；
- 任意命令、路径、环境、未知字段和 system-wide 目标在 Schema/实现两层均不存在或被拒绝；
- Helper 只能写固定 spool，且配额不足时不删除旧证据；
- 默认安装不启用服务、不改变 sysctl/capability；模式切换可预检、回滚和卸载；
- `cap_perfmon` 与 `paranoid3_helper` 分别完成真实短时验收，不能用 health 代替 perf 验收；
- wheel 不需要 Rust，原生包必须包含经过测试且与目标架构一致的 Helper。
