# PerfLens 已知问题

简体中文 | [English](known-issues.md)

本文记录已经复现、具有明确边界和临时处理方法的问题，包括已经修复的问题。
不要通过降低部署器安全检查来规避问题；升级前仍可按对应版本的临时方法处理。

## KL-2026-08-09：部分 VMware/混合架构主机的硬件 PMU 返回零计数（已提供自动降级）

- 现象：软件事件 `task-clock` 等可以计数，但 `cycles`、`instructions` 在持续 CPU 负载下
  仍返回 0，或 `perf` 报 `not supported`、`not counted`、`ENOMEM`；
- 边界：这通常是虚拟 PMU 暴露、宿主机 Hyper-V/VBS、VMware 与 Intel 混合 P/E 核 PMU
  兼容问题，不是来宾 CPU 算力不足，也不能由 root 权限修复；
- 当前处理：`record`/`stat` 默认采用 `event_source=auto`。Collector 用最多 250ms 的
  同 PID 固定探测判断硬件计数是否有用；失败后，`stat` 使用固定软件事件，`record`
  使用 `cpu-clock`，并在结果和中文摘要中明确提示降级；
- 仍可完成：CPU 时间、上下文切换、迁移、缺页、on-CPU 热点、调用路径、源码定位、
  火焰图以及同事件来源的前后对比；
- 不能宣称：IPC、硬件缓存未命中率、分支未命中率和其他微架构结论。

需要硬件证据的实验应选择 `hardware_required` 并让失败保持可见；已知 PMU 不可用且需要
稳定 A/B 时选择 `software_only`。不要把一份 hardware 基线与一份 software 候选结果
直接比较。仍可在完全关机后调整 VMware vPMC/宿主虚拟化设置，但 PerfLens 的软件降级
不再要求用户先解决该平台问题才能继续常规性能优化。

## KI-2026-08-10：Helper 的 stat 成功但 record 无法合成目标映射（已修复）

- 影响范围：已撤回的 `v0.2.0` `paranoid3_helper` 原生包，其中 root Helper unit 只包含
  `CAP_PERFMON` 与 `CAP_SYS_ADMIN`；默认 `cap_perfmon` 和普通组件不受影响；
- 现象：明确使用 `--event-source software_only` 的 `verify-collector` stat 已成功，但
  `accept-collector` 进行软件 record 时仍返回 `EXTERNAL_TOOL_FAILED`。等价的临时
  `perf record` 在两项 capability 下失败，加入 `CAP_SYS_PTRACE` 后能实际写出采样；
- 根因：`CAP_PERFMON` 负责 performance event 访问，但这条附加 PID 的 `perf record`
  路径还需要 ptrace 等价访问，才能读取已经授权目标的进程映射并合成可用采样元数据；
  stat 成功没有覆盖该路径；
- 修复：重新发布的同版本 Helper unit 上限精确为 `CAP_PERFMON`、`CAP_SYS_ADMIN` 和
  `CAP_SYS_PTRACE`。类型化 PID 协议、目标 UID/启动时间、过期、单次消费、事件/时长/输出
  上限和固定 spool 均不改变；Agent、Skill、MCP 与 Python Broker 不增加 capability；
- 升级安全：`perflens-admin upgrade --dry-run` 会在 `helper_capability_expansion` 中显示
  `CAP_SYS_PTRACE`。正式升级在没有 `--acknowledge-privileged-helper-risk` 时，会在写 unit
  和重启服务前拒绝。

安装替换包后执行：

```bash
sudo perflens-admin upgrade --dry-run
sudo perflens-admin upgrade --acknowledge-privileged-helper-risk
perflens accept-collector --authorize-host-acceptance
```

旧参数 `--acknowledge-cap-sys-admin-risk` 仍兼容，但新指南使用覆盖完整边界的通用名称。

## KI-2026-08-10：Helper 将 Linux perf 的 NUL 结尾 ACK 误判为失败（已修复）

- 影响范围：已撤回的 `v0.2.0` `paranoid3_helper` 原生包；默认 `cap_perfmon` 模式
  不经过该私有 Helper 协议；
- 现象：服务健康握手通过，策略也允许固定软件事件，但 `accept-collector` 或明确指定
  `--event-source software_only` 的 `verify-collector` 仍立即返回 `EXTERNAL_TOOL_FAILED`；
  Helper spool 只出现已消费计划标记，没有性能产物；
- 根因：perf 的 control fd 文档把完成响应写作 `ack\n`，Linux 6.12 实现却按 C 字符串
  大小写出 `ack\n\0`。旧 Helper 第一次按行读取后把 NUL 留在缓冲区，导致下一次响应被
  读成 `\0ack\n` 并安全拒绝；只写 `ack\n` 的测试替身没有覆盖真实帧；
- 修复：重新发布的 `v0.2.0` 对 ACK 使用最多 16 字节的严格二进制解析，只允许响应前
  存在实现产生的 NUL，其他内容和超长响应仍拒绝；启动屏障改用 perf 支持的非变更
  `ping`，因此仍会在重新校验 PID 所有者和启动时间之后、启用事件之前完成绑定确认；
- 回归测试：测试替身现在逐次发送真实的 `ack\n\0`，并覆盖连续响应跨帧时遗留 NUL 的
  情况。

这是 Helper 协议兼容性问题，不是 `perf_event_paranoid=3`、软件事件策略或 VMware PMU
降级失败。安装重新发布的同版本包并运行 `sudo perflens-admin upgrade` 后，再执行普通用户
验收；无需降低 sysctl，也不要给 Agent、MCP 或 Python Broker 增加权限。

## KI-2026-08-07：已撤回的 v0.2.0 Helper unit 无法通过 systemd USER 阶段（已修复）

- 影响范围：已撤回的首批 `v0.2.0` 原生 `perflens-collector` DEB，在 Debian 13 上选择
  `paranoid3_helper`；默认 `cap_perfmon` 模式不受影响；
- 现象：部署健康检查失败，journal 显示 `Failed to drop keep capabilities flag` 和
  `Failed at step USER`；Broker 随后可能因为 Helper 运行目录不存在而在 NAMESPACE 阶段失败；
- 根因：Helper unit 过早设置 `keep-caps-locked`，但 systemd 在 USER 设置阶段仍需清除
  `PR_SET_KEEPCAPS`，锁定状态使该安全转换被内核拒绝；
- 修复：重新发布的 `v0.2.0` 产物移除冲突的 secure-bit 锁；这项 USER 阶段修复本身没有
  扩权。最终替换 unit 为解决 record 问题使用上文单独说明并要求管理员确认的三项
  capability 边界；Agent、MCP 与 Python Broker 仍不增加 capability。

部署器失败后会撤回本轮新配置、两个 unit 和 Socket，不会留下半部署状态。不要手工修改
已安装包或放宽 systemd 边界；请安装重新发布的 `v0.2.0` 产物，再用原配置重新部署。

## KI-2026-08-07：Helper 将正常的限时 SIGINT 结束误判为失败（已修复）

- 影响范围：已撤回的首批 `v0.2.0` `paranoid3_helper` 实现；
- 现象：部署和认证健康握手均成功，但执行
  `perflens accept-collector --authorize-host-acceptance` 返回 `EXTERNAL_TOOL_FAILED`，技术信息为
  `Privileged perf returned a non-zero result`；
- 根因：到达请求时长后，Helper 会先禁用事件，再向附加 PID 的 `perf` 发送 SIGINT，让它刷新并
  关闭产物；Linux 会把这次正常结束表示为 signal 2/状态 130，旧逻辑却按外部失败处理；
- 修复：重新发布的 `v0.2.0` 只在 Helper 自己成功进入限时关闭路径并发送 SIGINT 时接受该状态。
  提前收到 SIGINT、其他信号、普通非零退出、控制消息失败以及空或不安全产物仍会安全拒绝。

这项修复不会让主机原本不存在的性能计数器变得可用。如果验收继续运行后返回
`PROFILE_PARSE_FAILED`，且所有指标都是 `not_supported` 或 `not_counted`，应检查主机 PMU；虚拟机
通常还需要在虚拟化平台中启用“虚拟化 CPU 性能计数器”。

## KL-2026-08-07：Rust Helper 私有 spool 曾不支持归档和清理（已修复）

- 影响范围：已撤回的 `v0.2.0` 最初实现中的 `paranoid3_helper` 模式；
- 修复状态：重新发布的 `v0.2.0` 产物已修复；
- 原行为：`archive-spool`、`verify-spool-archive` 和 `prune-archived-spool` 明确返回
  `UNSUPPORTED_FORMAT`，避免误读或删除普通 `/var/lib/perflens` 中的文件；
- 修复内容：归档生命周期现在根据已审查的权限模式选择真实 spool，分别验证 Helper
  目录/墓碑的 `root:perflens-internal` 身份和产物的 `root:perflens` 身份，并在 manifest
  中绑定权限模式与 spool 路径。

使用已撤回产物的现有部署应先换装重新发布的 v0.2.0 包，再清理 Helper spool。不要手工
删除未知证据或修改目录权限来绕过检查。

## KI-2026-08-06：DEB 原地升级后入口可能继续加载旧版本字节码

- 影响版本：从 `v0.1.2` 原地升级到 `v0.1.3` 的原生 DEB；
- 修复状态：当前开发分支已修复，将随下一版本发布；
- 现象：`dpkg-query` 显示 `0.1.3-1`，但 `perflens --version` 或其他入口仍显示
  `0.1.2`；
- 根因：可复现 DEB 固定了 Python 源文件时间，旧版遗留的同路径 `.pyc` 可能继续满足
  时间戳/大小校验；旧包又没有在升级配置阶段清理它。

当前开发修复包含两层防护：原生启动器在导入 PerfLens 前禁用写入并把 cache 查找移到
包内不存在的固定隔离前缀，因此不再读取旧的 inline `__pycache__`；主包 `postinst` 还会
在 `configure` 阶段只清理固定 `/usr/lib/perflens` 下遗留的 `.pyc/.pyo` 和空 cache
目录。普通 wheel 不受 DEB maintainer script 影响。

已经遇到问题的 `v0.1.3` 用户可以先确认包版本，然后删除固定运行时中的旧 cache：

```bash
dpkg-query -W -f='${Package} ${Version}\n' perflens perflens-collector
sudo find /usr/lib/perflens -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
sudo find /usr/lib/perflens -depth -type d -name '__pycache__' -empty -delete
hash -r
perflens --version
```

不要删除整个 `/usr/lib/perflens`；它属于已安装的主包。

## KI-2026-08-05：`umask 0002` 导致 Collector 配置被部署器拒绝

- 影响版本：`v0.1.2`；
- 修复版本：`v0.1.3`；
- 状态：已修复；`v0.1.2` 用户仍可使用下方安全临时处理；
- 影响范围：使用 `perflens init --prepare-collector` 或
  `perflens setup --prepare-collector` 新生成的 `collector.toml`；
- 不影响：已经成功安装到 `/etc/perflens/collector.toml` 的系统策略、已有 Profile
  分析，以及不需要 Collector 的只读使用方式。

### 现象

在使用常见协作型 `umask 0002` 的系统上生成 Collector 资产后，普通用户执行预检：

```bash
perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml" \
  --dry-run
```

可能收到：

```text
错误代码: PATH_SAFETY_VIOLATION
阶段: collector_deploy
技术信息: Collector config must be invoking-user/root owned,
non-writable by group/other, and bounded
```

检查时通常会看到配置权限是 `664`：

```bash
umask
stat -c '%a %U:%G %n' \
  "$PWD/perflens-setup/collector-assets/collector.toml"
```

示例输出：

```text
0002
664 link:link /home/link/perflens-bootstrap/perflens-setup/collector-assets/collector.toml
```

### 根因

`v0.1.2` 的 Collector 资产生成器创建文件后没有显式设置最终权限，而是受调用进程
`umask` 影响。基础创建权限 `0666` 在 `umask 0002` 下变成 `0664`，因此同组用户仍可
写入配置。部署器会拒绝任何可被组或其他用户写入的策略文件；这是正确的安全行为，
不应放宽。

### `v0.1.3` 修复

`v0.1.3` 不再依赖调用进程的 `umask`：生成目录固定为 `0700`，
`collector.toml` 固定为 `0600`，systemd unit 和 sysusers 模板固定为 `0644`。
部署器的属主、普通文件、大小以及组/其他用户不可写检查保持不变。

升级到 `v0.1.3` 后，重新运行 `perflens init --update --prepare-collector` 生成的
配置可以直接进行 `perflens-admin deploy --dry-run`。已有且未修改的 v0.1.2 Skill
也会同时从旧目录名安全迁移到 `.agents/skills/perflens` 或
`.claude/skills/perflens`。

### `v0.1.2` 临时处理

在包含 `perflens-setup` 的初始化目录中，以生成该文件的普通用户执行：

```bash
chmod 600 "$PWD/perflens-setup/collector-assets/collector.toml"

stat -c '%a %U:%G %n' \
  "$PWD/perflens-setup/collector-assets/collector.toml"
```

确认结果为 `600 <当前用户>:<当前组> .../collector.toml` 后重新预检：

```bash
perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml" \
  --dry-run
```

预检通过后才正式部署：

```bash
sudo perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml"
```

不要使用 `sudo` 跳过 `chmod`，也不要让配置保持 `664`。正式部署会把经过检查的策略
安装为 root 管理的 `/etc/perflens/collector.toml`。

### 是否每个项目都要处理

不需要。Collector 对同一个 Linux 普通用户是主机级服务，首次部署成功后，该用户的
其他项目只需在项目目录运行：

```bash
perflens init --client codex
```

只有重新生成部署配置并再次执行首次部署时，`v0.1.2` 才可能再次遇到此问题。正常软件
升级使用 `perflens-admin upgrade`，不应重复 `undeploy` 和 `deploy`。

### 修复验收

`v0.1.3` 已满足：

- 生成器显式把 `collector.toml` 设置为 `0600`，不依赖调用者 `umask`；
- 在 `umask 0002` 和更宽松的测试环境中仍生成不可被组/其他用户写入的配置；
- `perflens-admin deploy --dry-run` 可直接接受新生成、未被人工修改的配置；
- 保留部署器现有的属主、普通文件、大小和不可组写安全检查；
- 增加回归测试，防止安装引导与部署器再次产生互相不兼容的权限要求。
