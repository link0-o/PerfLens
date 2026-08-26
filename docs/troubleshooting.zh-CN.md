# 故障排查

简体中文 | [English](troubleshooting.md)

如果错误只出现在某个已发布版本，先查看[《已知问题与临时处理》](known-issues.zh-CN.md)。
其中记录了 `v0.1.2` 在 `umask 0002` 下生成组可写 Collector 配置的问题，以及
`v0.1.3` 的修复与旧版本临时处理。
如果修改的是 v0.3.2 Docker 优化采集链路，还要执行
[《防回归手册》](v0.3.2-regression-playbook.zh-CN.md)中的时序和测试检查。

## 先运行统一状态检查

不确定问题出在哪一层时，先运行：

```bash
perflens status --project /绝对路径/你的项目
```

如果 `setup` 使用过 `--output-directory`，请复制该次引导显示的完整命令，或同时传入
`--setup-directory /绝对路径/你的项目/对应引导目录`。否则默认值可能检查到更早的
`perflens-setup`，从而把已经配置的自动采集显示成“未配置”。状态摘要底部会给出当前
场景对应的下一条恢复或验收命令。

这条命令只读检查引导目录、Skill、项目 `.codex/config.toml` 是否与本次引导匹配、
Collector 资产、Socket、当前登录
会话的 `perflens` 组身份和本机 perf 条件。前置条件通过后，它还会执行一次最长
500 毫秒的只读健康握手，并通过内核 `SO_PEERCRED` 复核专用服务身份；遗留 Socket、
无响应服务、畸形协议或错误 UID 都不会被判定为就绪。它不会采样或附加进程；显示
“可进行真实短时验收”也不等于 perf 已经采集成功，仍需执行
`perflens accept-collector --authorize-host-acceptance`。

项目 MCP 状态还会重新验证 `.codex/config.toml` 中的命令路径。若 pipx/uv 环境被移动、
入口不再可执行或可信符号链接被替换，状态会显示配置不完整；使用新的输出目录重新运行
`perflens setup`，检查差异后重启 Codex。

需要保存机器可读结果时使用：

```bash
perflens status \
  --project /绝对路径/你的项目 \
  --output perflens-status.json
```

## 错误输出给人看还是给程序解析

`perflens` 和 `perflens-admin` 的业务错误默认显示中文摘要。它保留稳定错误代码、错误
ID 和有界技术信息，但不是 JSON。脚本不要从中文文本提取字段，应使用：

```bash
perflens --json-errors <子命令> ...
perflens-admin --json-errors <子命令> ...
```

全局选项必须位于子命令前，也可以设置环境变量 `PERFLENS_JSON_ERRORS=1`。这只改变错误
展示，不改变正常输出、退出码、安全检查或版本化 `ErrorArtifact`。Typer 自身在参数尚未
进入 PerfLens 业务层时产生的用法错误仍采用框架格式。

## Collector Socket 不存在或当前用户不可访问

- 确认管理员已经执行 `perflens-admin deploy`；
- 使用 `systemctl status perflens-collector.service` 和 `journalctl` 查看服务错误；
- 确认 `/run/perflens/collector.sock` 存在且属于 `perflens` 组；
- 用户被加入组后必须重新登录，仅打开一个新子终端可能不会刷新组身份；
- 不要通过让 MCP 或 Agent 使用 root 来绕过 Socket 权限。

## 用结构化 Collector 日志定位请求

Collector 写到 stderr 的运维事件由 systemd 收入 journal，每行都是独立、有界的 JSON。
查看原始事件时使用：

```bash
journalctl -u perflens-collector.service --since today -o cat
```

`event_schema_version` 当前为 `1.0`。常见 `event` 包括 `collector_started`、
`collection_completed`、`request_rejected`、`collector_stopped` 和
`collector_start_failed`。拒绝事件包含 `request_id`、稳定 `error_id`、`error_code`、
`stage` 和已认证的 `peer_uid`；使用 `--json-errors` 时，客户端错误的 `details.request_id`
和 `error.error_id` 可与它关联。

日志不会记录目标 PID、命令、环境、Profile 内容、perf stderr、策略路径、spool 路径或
Python traceback，单条事件最多 2 KiB。`request_id = "unknown"` 表示请求在通过 JSON
结构校验前已经失败。启动失败只输出一个 `collector_start_failed` 后以非零状态退出；
结合 `error_code`/`stage` 检查配置和权限，不要为了获得 traceback 放宽服务隔离。

## Collector 配置版本不支持

生成的 `collector.toml` 包含 `policy_version = 1`。缺少该字段的旧版配置按版本 1
读取；其他版本会在部署或服务启动前被拒绝。不要为了绕过错误直接删除未知字段，
应使用匹配版本的 PerfLens 重新生成配置并审查差异。

## Collector 返回 `RESOURCE_LIMIT_EXCEEDED`

如果错误提到 spool 配额或文件系统空闲余量，说明 Collector 在启动 perf 前无法为本次
计划的最坏输出预留空间。先运行只读命令 `perflens-admin spool-status`，它会按
`/etc/perflens/collector.toml` 汇总 `/var/lib/perflens` 的文件数量、逻辑大小、
所在文件系统剩余空间和当前最多可采集字节数，并标出具体边界。需要完整机器可读证据
时加 `--json`。然后对照策略中的
`max_spool_bytes`、`max_spool_artifacts`、`min_free_bytes`。先审查并归档证据，再明确
删除不再需要的文件；不要让 Agent 自动删除或通过无限提高配额掩盖磁盘问题。

如果结果为 `目录中存在不安全项目`，不要让 Agent 尝试清理。先停止 Collector，确认
异常项不是仍在使用的证据或管理员文件，再人工处理；`spool-status` 本身不会跟随链接
或删除任何内容。

不要用 `rm` 或 Agent 自动任务按 mtime 清空 spool。正常释放空间应遵循
`archive-spool --dry-run` → 创建 root 管理归档 → 复制到独立存储 →
`prune-archived-spool --dry-run` → 显式授权清理的顺序。

若 `archive-spool` 报告 `unmanaged entry`，说明目录里有临时采集文件、手工文件、链接
或未知命名；它不会猜测哪些可以删除。停止 Collector 后检查该项目。若
`prune-archived-spool` 报告身份或 SHA-256 不匹配，表示归档或源文件在归档后发生变化；
不要放宽校验或继续删除，应保留两边并人工比对。归档父目录和归档本身必须由 root
管理且不可组写，避免清理期间备份被替换。

## `upgrade` 拒绝升级或升级后恢复

`perflens-admin upgrade` 只读取固定的 `/etc/perflens/collector.toml`，并且只替换带
PerfLens 托管标记、属主可信、没有组/其他用户写权限的 unit。若传入替代策略、unit 被
手工改成未知服务、路径是符号链接或权限过宽，命令会在重启前拒绝。先运行
`sudo perflens-admin upgrade --dry-run`，再用 `systemctl cat
perflens-collector.service` 审查差异，不要放宽检查。

如果新 unit 已写入但重启或 Socket 检查失败，命令会尝试恢复旧 unit，并再次执行
`daemon-reload` 和 `restart`。看到“could not be fully restored”时，不要继续自动重试；
应立即检查 unit 内容、`systemctl status perflens-collector.service` 和对应 journal，确认
当前实际加载的版本后再处理。管理员策略和 spool 证据不会在升级中删除。

## `update-policy` 拒绝配置或更新后恢复

`perflens-admin update-policy` 要求一个独立、属主可信、组和其他用户不可写、最大
256 KiB 的 UTF-8 TOML 候选文件；不要直接把
`/etc/perflens/collector.toml` 作为候选。先执行 `--dry-run`。它会拒绝未知字段、越界
参数、改变唯一授权 UID、迁移固定 spool 或 `privilege_mode`、符号链接或不可信的
`perf` 路径。权限模式切换需要审查后停机卸载并重新部署，因为 systemd 服务拓扑不同。

如果候选已写入但重启或身份验证健康检查失败，命令会原子恢复原策略并再次重启。
看到 “previous policy could not be fully restored” 时不要连续重试；检查当前配置哈希、
`systemctl status perflens-collector.service` 和 journal。历史产物与 service unit 不会被
该命令修改。

## service 已启动但部署仍报告 Socket 失败

部署和升级不会只看 `/run/perflens/collector.sock` 是否存在，而会连接并发送一次只读
`health` 请求。服务端检查调用方 Unix peer UID，客户端通过内核 `SO_PEERCRED` 复核
响应 PID/UID，管理员命令还要求专用 `perflens` 服务 UID。若文件存在但无人监听、服务
身份错误、协议版本不兼容、调用 UID 未授权或响应损坏，命令都会等待后失败；升级时还
会恢复旧 unit。先检查 `systemctl status` 与 journal，不要手工创建 Socket 文件，也不要
通过跳过握手把服务标记为成功。

## `undeploy` 拒绝移除 service

`perflens-admin undeploy` 只删除带 PerfLens 托管标记、所有者可信、且没有组/其他
用户写权限的固定 unit。旧版或手工修改过的 unit 会被拒绝，避免管理员命令误删
未知服务。先用 `systemctl cat perflens-collector.service` 审查内容；确认是旧版 PerfLens
文件后再按部署文档手工迁移，不要通过放宽权限检查绕过。

## 主动 perf 采样被拒绝

PerfLens 会把 `perf` 的有限 stderr 作为 `EXTERNAL_TOOL_FAILED` 返回。请检查：

- `/proc/sys/kernel/perf_event_paranoid`
- 当前用户的 capability
- 容器安全策略
- tracepoint 和 debugfs/tracefs 的访问权限

PerfLens 不会执行 sudo、修改 sysctl、授予 capability、挂载 tracefs 或降低主机安全策略。请让系统管理员提供经过批准的采样环境，或在有权限的机器上采集 Profile 后交给 PerfLens 分析。

## 无法解析已有 perf.data

`perf.data` 往往依赖采集机器的 `perf` 版本、内核和二进制环境。优先使用与采集端兼容的 `perf`，并通过 `--perf-path` 传入它的绝对路径。

如果仍不兼容，请在采集机器上导出文本：

```bash
perf script --ns \
  -F comm,pid,tid,cpu,misc,time,event,period,ip,sym,dso,srcline \
  -i perf.data > profile.perf-script
```

然后使用：

```bash
perflens analyze-perf-script \
  --input profile.perf-script \
  --output build/analysis.json
```

PerfLens 不直接解析 `perf.data` 二进制格式。

## MCP 分析 perf.data 提示没有进程执行权限

在 `perflens-mcp` 的参数中加入：

```text
--allow-process-execution
```

修改配置后需要重启 MCP 客户端。对于 Codex，可用 `codex mcp list` 或 `/mcp` 确认新的配置已经生效。

## 找不到符号或源码行

请检查：

- Profile 对应的 DSO 是否存在。
- Build ID 是否匹配。
- 独立调试文件和 debug link 是否可用；PerfLens 只接受 CRC32 与 `.gnu_debuglink` 一致，
  或 Build ID 与原 ELF 一致的候选，并会在解析前再次核验；
- 容器路径、构建路径和本地源码路径是否正确映射。
- 是否安装了 `llvm-symbolizer` 或 `addr2line`。

源码定位只接受已验证的模块相对偏移。PerfLens 不会根据单独的运行时 IP 猜测 ASLR 或 PIE 基址。缺失的符号会保留为 unknown，而不会被伪造。

## MCP 拒绝读取路径

输入 Profile、二进制、调试文件和源码工作区都必须位于某个 `--allowed-root` 之下。服务启动时会规范化路径并检查真实位置，符号链接也不能绕过边界。

为新的工作区增加一个明确的 allowed root：

```text
--allowed-root /absolute/path/to/workspace
```

不要为了省事把 `/` 或用户主目录整体设为 allowed root。

## MCP 拒绝写入产物

确认服务参数中包含 `--allow-writes`，且目标位于 `--artifact-root` 下。MCP 不覆盖已有
产物路径；同一 ID 只有已有字节完全相同时才视为幂等成功。同 ID 不同内容、FIFO、
软链接、额外硬链接或不安全权限都会被拒绝，PerfLens 也不会覆盖源 Profile。

可以换一个新文件名；若该路径本应由 PerfLens 管理，应先调查冲突来源，不要自动删除证据。

结构化写入错误还应检查 `details.published`：`false` 表示目标未改变，修复原因后可安全
重试；`true` 表示完整字节已经发布，但目录持久化或路径身份无法确认。此时必须先验证
目标文件，避免把一次不确定的存储确认变成意外覆盖。

## 只有部分分析结果

单条坏记录会被跳过并写入有界诊断。结构性资源限制则会使分析失败，避免静默丢失精确数据。

请检查分析 JSON 中的：

- warnings 和诊断摘要
- 已解析与跳过的记录数
- unknown symbol/DSO/source 的数量
- 是否触发输入大小、行长、栈深、唯一帧或调用路径上限

不要只根据一个热点百分比下结论。

## Benchmark 比较结果是“不确定”

常见原因包括：

- baseline 与 candidate 的机器、内核、CPU、频率策略或工作负载不同。
- 重复样本不足。
- 波动太大。
- 实际效果没有达到配置的意义阈值。
- 只有 Profile 百分比变化，没有吞吐量或延迟等外部指标。

这不是工具失败，而是现有证据不足以证明改进或回退。

## Codex 没有发现 Skill

Skill 位于仓库的：

```text
.agents/skills/perflens
```

请确认从 PerfLens 仓库或包含该目录的工作区启动 Codex，然后显式输入：

```text
使用 $perflens 分析这个 Linux Profile。
```

Skill 和 MCP 是独立组件。发现 Skill 不代表 MCP 已经连接；请另外用 `codex mcp list` 检查名为 `perflens` 的 MCP Server。
