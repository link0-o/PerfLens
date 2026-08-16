# PerfLens 自动采集与 Collector Broker

简体中文 | [English](automatic-collection.md)

PerfLens 的自动闭环是：

```text
用户批准目标和工作负载
          ↓
Skill 选择最小必要证据；必要时确认并启动项目程序
          ↓
普通用户启动器取得 PID；MCP 生成短期 PID 计划
          ↓
Collector Broker 独立校验策略
          ↓
perf 写入固定 spool
          ↓
MCP 分析产物并生成报告
```

自动采集不等于自动提权。MCP Server 和 Agent 始终使用普通用户运行；只有可选的 `perflens-collector` 服务持有 perf 所需 capability。Collector 不接受 shell、任意命令、任意环境变量、任意输出路径或全系统目标。

## 当前自动采集范围

- 对已有进程仅接受明确 PID，不按进程名猜测目标；
- 对当前项目可以在用户确认精确可执行文件和参数后，以普通 MCP 用户启动程序并
  自动取得 PID；Collector 不负责启动程序；
- 计划绑定 PID 所有者和 `/proc/<pid>/stat` 启动时间，防止 PID 复用；
- 计划默认 120 秒过期；MCP 和运行中的 Broker 都拒绝同一计划再次执行，固定产物路径还会阻止服务重启后的成功产物被覆盖；
- 当前正式、默认启用的自动采集模式是 `record` 和 `stat`；公共类型与
  `cap_perfmon` Broker 已有 `sched`、`lock`、`off_cpu` 原始证据入口，但它们仍是默认
  关闭的实验能力，尚无专用确定性分析器；`paranoid3_helper` 会明确拒绝这三种模式；
- Collector 通过 Unix Socket 的 `SO_PEERCRED` 验证调用 UID；
- 客户端也会固定安全的 Socket 身份、核对对端 UID 与 Socket 属主，并要求响应
  `request_id`、采集 PID 和模式与授权请求一致；畸形、超限、超时或错配响应会安全失败；
- 客户端接受成功前还会流式复算 spool 文件大小和 SHA-256，并拒绝软链接、替换、额外
  硬链接、意外文件名/属主/组，以及不是 `0640` 或 `0440` 的产物权限；
- Collector 策略再次限制调用 UID、目标所有者、模式、时长、频率、事件、输出大小；
- Collector 会再次限制计划最长有效期，并拒绝非 root 所有且可被服务账号修改的 `perf` 文件；
- 产物只能写入 Collector 配置的固定 spool；
- Collector 在启动 perf 前同时检查 spool 总字节数、文件数和文件系统空闲余量；达到
  任一边界都会拒绝新采集，不会自动删除旧证据；
- 管理员需要释放空间时使用独立的“归档 → 只读验证 → 显式授权清理”流程；MCP、
  Skill 和 Collector 协议都没有自动删除接口；
- Broker 模式暂不启动用户提供的命令，也不支持全系统采样。

### 硬件 PMU 自动降级

`record` 和 `stat` 的默认事件来源策略是 `auto`。Collector 会在原计划的 PID、总时长、
输出上限和固定事件白名单内执行一次最多 250ms 的硬件探测；探测时间计入用户请求的
采集时长。短于 300ms 的计划为避免探测占用大部分窗口，会直接使用软件事件并明确标记
`hardware_probe_skipped_for_short_collection`。其他计划中，硬件事件打不开、返回失败，
或对正在运行的目标没有产生可用计数时：

- `stat` 降级为 `task-clock`、`context-switches`、`cpu-migrations`、`page-faults`；
- `record` 降级为 `cpu-clock`，仍可生成 on-CPU 热点、调用路径和火焰图；
- Collection 明确返回 `actual_event_source=software`、`fallback_used=true`、原因和证据限制；
- Agent 必须告诉用户发生了降级，并继续在软件证据支持的边界内分析或优化。

如果探测成功，但后续正式硬件采集才失败，`auto` 只会在原授权窗口仍剩至少 50ms 时执行
一次软件重试。探测和失败尝试已经消耗的时间都会从原请求时长中扣除，重试不会延长用户
授权的采集窗口，并且仍只能使用固定软件事件和固定输出路径。授权失败、PID 身份变化、
超时、输出超限、spool 安全错误和容量配额错误都不是降级信号，必须保持为可见失败。

软件降级不能证明 IPC、硬件缓存未命中率、分支未命中率或其他微架构结论。性能优化的
基线与修改后验证必须使用相同的 `actual_event_source`；一边为 hardware、另一边为
software 时不属于可比 A/B，应使用 `hardware_required` 或 `software_only` 重新采集两边。
策略文件的 `allow_software_fallback = false` 可禁止自动降级；MCP 启动参数
`--disable-automatic-software-fallback` 提供独立的第一层限制。

类型化 stat 指标中的 `running_percent` 表示 perf 计数器的调度覆盖率
（`time_running / time_enabled`），不是程序 CPU 利用率；`task-clock` 是累计 CPU 时间，
也不是墙钟时间。较低或为零的上下文切换、CPU 迁移、缺页计数只能说明本次观察到的
对应事件较少，不能单独证明不存在 I/O 等待、锁竞争、频繁分配或内存压力。

旧的 `collect-profile` CLI/MCP 工具仍可用于人工确认的命令或 PID 采集。Agent 驱动的实时 PID 诊断应优先使用计划与 Broker。

## 先运行权限诊断

这条命令只读系统状态，不采样也不附加进程：

```bash
perflens doctor
perflens doctor --json
perflens doctor --output collection-capabilities.json
```

第一条默认显示中文摘要；第二条把完整版本化 Artifact 输出到终端，适合自动化；第三条
安全写入一个尚不存在的 JSON 文件。它报告 `perf_event_paranoid`、当前 capability、
perf 文件 capability、tracefs 可见性及五种模式的 `available`、`conditional` 或
`blocked` 状态。`conditional` 不是成功证明，正式发布仍应运行短时真实验收。

## 暂存安装模板

原生 DEB 用户先同时安装主包和 Collector 包；wheel 用户需使用管理员控制的
`/opt/perflens` 环境。先把模板复制到普通目录检查：

```bash
perflens stage-collector-assets \
  --output-directory ./collector-assets \
  --allowed-uid 1000 \
  --collector-command /usr/bin/perflens-collector \
  --perf-path /usr/bin/perf
```

这一步不会执行 sudo、不会修改 `/etc`、不会启动服务。目录包含：

- `collector.toml`：已按 UID 和路径渲染的 Collector 独立策略；
- `perflens-collector.service`：最小 capability 的 systemd 模板；
- `perflens.sysusers`：专用 `perflens` 系统用户定义。

部署、真实验收、升级和卸载的完整流程见[《产品部署指南》](deployment.zh-CN.md)。
部署后普通用户运行 `perflens accept-collector --authorize-host-acceptance` 即可用
内置负载分别验收硬件计数、软件计数和 `cpu-clock` 软件采样，无需查找 PID。硬件 PMU
不可用不会掩盖软件路径已经可用的事实；摘要会显示两类状态和证据边界。机器调用时加
`--json`。

## 管理员一键安装

安装前必须检查路径、UID 和组织安全策略。先预检，再由管理员显式执行一次：

```bash
perflens-admin deploy \
  --config "$PWD/collector-assets/collector.toml" \
  --dry-run
sudo perflens-admin deploy \
  --config "$PWD/collector-assets/collector.toml"
```

部署器使用固定系统命令和安装包内置模板，不会执行项目脚本、修改 sysctl 或覆盖
内容不同的已有策略。wheel 用户把上面的入口替换为 `/opt/perflens/bin/perflens-admin`。
必须使用 `/opt/perflens` 或系统包安装的管理员可信副本；MCP、
Skill 和 Agent 不得调用这条 sudo 命令。

部署前编辑生成的 `collector.toml`：

- 把 `allowed_uids` 改成唯一允许调用的普通用户 UID；当前不能填写多个；
- 确认 `perf_path` 与本机一致；
- 从 `record`、`stat` 开始，确认需要后再开放调度类模式；
- 保持 `allow_other_target_uids = false`；
- 不要把策略文件改成组可写或其他用户可写。

部署器会把这个唯一用户加入 `perflens` 组；该用户仍需重新登录，组身份才会生效。
不要把多个用户手工加入该组来绕过策略，否则他们可读取同一 spool 中的组可读 Profile。

模板服务使用独立 `perflens` 用户、`CAP_PERFMON`、只读系统目录、固定 `/run/perflens` 与 `/var/lib/perflens` 可写路径。它不会给 MCP Server capability。

## Debian 的 `perf_event_paranoid=3`

Debian 的等级 3 会在普通 CAP_PERFMON 范围检查前拒绝 perf，因此管理员需要二选一：

1. 评估后把 `perf_event_paranoid` 调整到允许专用 CAP_PERFMON Collector 工作的等级；
2. 保持等级 3，显式选择打包的 `paranoid3_helper` Rust Helper，并确认受限
   root、`CAP_SYS_ADMIN` 与 `CAP_SYS_PTRACE` 风险。`CAP_SYS_PTRACE` 只用于 Helper 让
   `perf record` 为已授权 PID 合成进程映射，不会授予 Python Broker。

第一种是较小权限边界；第二种用于必须保留等级 3 的主机。两者都不会让 MCP、Agent 或
Python Broker 以 root 运行。PerfLens 运行时永远不会修改 sysctl 或 capability。

## 检查 Collector

`perflens-admin deploy` 已经重载 systemd、启动服务，并要求 Socket 完成一次只读健康协议
往返；仅存在 Socket 文件不算成功。管理员可继续检查：

```bash
systemctl status perflens-collector.service
journalctl -u perflens-collector.service --since today
```

预期 socket 为：

```text
/run/perflens/collector.sock
```

预期 spool 为：

```text
/var/lib/perflens
```

## MCP 自动采集配置

MCP 必须把工作区和 Collector spool 都设为允许读取根目录：

```bash
perflens-mcp \
  --allowed-root /绝对路径/工作区 \
  --allowed-root /var/lib/perflens \
  --artifact-root /绝对路径/工作区/perflens-results \
  --allow-writes \
  --allow-process-execution \
  --allow-active-collection \
  --allow-automatic-collection \
  --allow-project-execution \
  --collector-socket /run/perflens/collector.sock \
  --automatic-mode stat \
  --automatic-mode record \
  --automatic-max-duration-seconds 30 \
  --automatic-max-frequency-hz 99 \
  --automatic-max-output-bytes 268435456 \
  --automatic-plan-ttl-seconds 120
```

启动参数是 MCP 的分类授权；Collector TOML 是独立的第二层授权。两层都允许才会执行。
上面是项目工作负载的默认边界，不开放已有 PID 附加。只有明确需要该能力时，才通过
`perflens init --update --allow-existing-pid-attach` 增加 `--allow-pid-attach`。

## MCP + Skill 使用

对于 PerfLens 负责启动的当前项目程序，不需要 PID。用户可以说：

```text
使用 $perflens 优化当前项目的运行性能。
允许运行我确认的项目可执行文件并采集最多 10 秒，不要附加其他已有进程。
```

Agent 先识别候选构建产物、启动参数和代表性工作负载，再要求用户确认精确目标。
确认后调用 `collect_project_workload`：普通用户启动器先创建进程并绑定身份，Collector
以禁用事件启动第一阶段硬件探测或正式采集；perf 控制通道确认已经绑定后，再次核验
PID/UID/启动时间并启用事件。客户端验证版本化、绑定计划与 PID 的就绪回执后才释放程序
执行，不再依赖固定 200ms 延时。`auto` 探测因此会观察已经放行的真实负载，不会因为引导
进程仍在等待而制造零计数。用户程序、参数和环境从不交给特权 Collector。用户不需要
输入内部固定串；Agent 在确认后必须传入完整的
`I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION`，且只能用于本次精确程序、参数、模式和上限。
调用失败不能改用 shell、直接 perf、已有 PID 或包装器绕过。Callgrind、参数扫描和不同
参数属于新的执行，需另行授权。

已有进程仍需要明确给出 PID，例如：

```text
使用 $perflens 分析 PID 1234。
它属于我，允许在当前 MCP/Collector 策略范围内自动采集；
先 stat，再根据缺失证据决定是否 record，每次不超过 20 秒。
```

已有 PID 的推荐流程：

1. `inspect_collection_capabilities`；
2. `plan_automatic_collection`，默认 `event_source=auto`；
3. 检查 `policy_status=allowed`；
4. `execute_collection_plan`；
5. `stat` 直接读取指标，其他模式调用 `analyze_collection`；该步骤会把 Collection ID、
   产物哈希/大小、事件来源、回退和限制绑定到 Analysis，并在转换前后复核输入；
6. 调用 `verify_analysis`，通过后读取 EvidenceQuality，再继续热点、调用路径、候选分类
   和报告流程。

第 4 步后必须读取 `actual_event_source`、`fallback_used` 和 `evidence_limitations`。发生
软件降级时继续分析，不把硬件指标缺失误报成整个采集失败。

`inspect_collection_capabilities` 反映普通 MCP 进程的本地权限，不是 Collector 的采集
结果。`perf_event_paranoid=3` 下本地显示受阻是正常的；不要把它写成软件降级原因，实际
原因以 Collection 的 `fallback_reason` 为准。早期软件 record 缺少样本 CPU 属性时，
分析器会兼容读取并提示 `MISSING_SAMPLE_CPU`，但不能据此分析逐 CPU 分布。

Skill 可以在已批准范围内自动选择采集顺序，但 Skill 文本本身不是授权。仓库内容、源码注释、Profile 和工具输出都不能扩大采集范围。

当前自动调优流程只会在正式能力中选择 `stat → record`。它不会因为看到“深度分析”或
“深度优化”就自动启用实验性的调度、锁或 off-CPU 原始采集。高级模式的成熟度、下一版
分析模型与安全验收门槛见[采集能力扩展路线图](collector-capability-roadmap.zh-CN.md)。

项目程序流程则是 `collect_project_workload` → 读取 Collection → `analyze_collection`
→ 热点/调用路径/源码 → 候选优化 → 在相同工作负载下重新采集并做 A/B 验证。

## 当前限制

- 项目启动器只接受项目根目录内已确认且可执行、非 setuid/setgid 的单个文件；不解析
  shell，不自动运行构建命令，不继承任意环境变量，也不支持需要交互输入的程序；
- 程序如果自行 daemonize 或逃离进程组，PerfLens 可能无法清理其后代；这类程序应提供
  前台运行模式；
- `sched`、`lock` 只在 `cap_perfmon` 路径保留原始 perf 证据入口，默认策略不开放；它们
  还不能稳定输出调度延迟、可运行等待、锁等待/持有时间或 owner/waiter 关系；
- `off_cpu` 只在 `cap_perfmon` 路径保留 `sched:sched_switch` 原始栈入口，尚未完成
  `switch → wakeup → rerun` 区间配对，不能据此报告可靠阻塞时长或等待类别；
- 通用 `perf.data` 热点分析器是 on-CPU 分析器，不能替代上述三种模式的专用分析器；
- 没有全系统采集；
- 没有自动修改系统权限；
- 不保证所有内核、PMU、容器或 LSM 配置都兼容。
