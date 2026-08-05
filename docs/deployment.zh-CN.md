# PerfLens 产品部署指南

简体中文 | [English](deployment.md)

Debian 13 正式用户优先使用拆分的原生安装包，先阅读
[《Debian 安装包》](debian-packages.zh-CN.md)。下面的 wheel 流程主要用于开发
验收和其他 Linux 发行版。

PerfLens 应拆成普通用户分析端和系统 Collector 两部分部署：

```text
普通用户：perflens + perflens-mcp + Skill
                       │ Unix Socket
系统服务：专用 perflens 用户 + perflens-collector + CAP_PERFMON
```

管理员只负责首次安装、策略和主机权限。日常 Agent、MCP 和分析命令不使用 sudo，也不持有 perf capability。

## 从当前 wheel 部署

以下流程适合开发验收和不使用正式 DEB 的系统。先在源码目录构建：

```bash
.venv/bin/python -m build
```

把 Collector 安装到系统可执行、但不在用户家目录中的独立环境：

```bash
sudo python3 -m venv /opt/perflens
sudo /opt/perflens/bin/python -m pip install \
  ./dist/perflens-0.1.2-py3-none-any.whl
```

这里的版本号只是示例，应替换为实际构建版本。正式离线部署应同时提供 wheelhouse 或完整系统包，不应在安装脚本中隐式访问网络。

普通用户首次安装和项目配置应先按照[《安装与首次使用》](../INSTALL.zh-CN.md)在目标项目运行 `perflens init`。本页主要面向需要部署系统 Collector 的管理员。

优先使用 `perflens setup --prepare-collector` 生成当前布局匹配的完整资产和可复制命令。
正式 DEB 会自动使用 `/usr/bin`；wheel/source 会使用下面的 `/opt/perflens`。只有自定义
管理员布局才需要手工运行 `stage-collector-assets --collector-command ...`。

获取普通用户 UID：

```bash
id -u <用户名>
```

以该 UID、正式 Collector 路径和本机 perf 路径生成部署资产：

```bash
perflens stage-collector-assets \
  --output-directory ./collector-assets \
  --allowed-uid 1000 \
  --collector-command /opt/perflens/bin/perflens-collector \
  --perf-path /usr/bin/perf
```

一套 Collector 当前必须且只能配置一个普通用户 UID。因为产物需要通过 `perflens` 组
提供给 MCP 读取，多个调用用户共享同一组和 spool 会造成跨用户 Profile 泄露，所以
策略、资产生成和一键部署都会拒绝多个 UID。需要多用户的服务器暂不应共享这一实例；
未来应采用每 UID 独立 service/socket/spool 或带身份校验的 Broker 读取协议。该命令
只生成可检查文件，不执行 sudo、不写 `/etc`、不启动服务。

## 管理员一键安装

先检查生成的 `collector-assets/collector.toml`。建议先用普通用户执行只读预检：
该文件已经为每个参数提供中英文注释，并标明常用可调项、固定路径和安全敏感项。

```bash
/opt/perflens/bin/perflens-admin deploy \
  --config "$PWD/collector-assets/collector.toml" \
  --dry-run
```

确认中文预检摘要中的 UID、`perf`、Collector 和目标路径无误后，管理员只执行一次：

```bash
sudo /opt/perflens/bin/perflens-admin deploy \
  --config "$PWD/collector-assets/collector.toml"
```

这条命令会完成以下固定操作：创建专用系统账号和目录、安装策略与 systemd unit、
把策略中的 `allowed_uids` 对应用户加入 `perflens` 组、重载 systemd、启动服务并等待
Unix Socket 完成一次有界、只读的健康协议往返。Collector 校验管理员/授权用户的
peer UID，管理员客户端也通过内核 `SO_PEERCRED` 确认响应进程属于专用 `perflens`
服务 UID；只有收到身份匹配的版本化 `status: ready` 才会报告成功。遗留但无人监听的
Socket 文件或错误 UID 的服务不会误判为就绪。
部署命令默认输出中文摘要，明确区分“预检通过但尚未修改系统”和“部署完成且健康握手
通过”，并显示下一步操作；自动化程序加 `--json` 可获得带 `schema_version` 的完整
版本化结果。它不执行配置里的命令，
不修改 sysctl 或 capability，也不会覆盖内容不同的已有配置。

`perflens-admin` 必须来自管理员控制的系统安装，例如 `/opt/perflens` 或正式
DEB；不要通过 `sudo` 执行用户家目录里可修改的 pipx 脚本。正式系统包安装后，
命令将简化为 `sudo perflens-admin deploy --config ...`。

生成目录中的 service 和 sysusers 文件用于审查；部署器使用安装包内置的可信模板，
不会执行或直接安装项目工作区提供的 service 文件。需要逐步排错时才参考这些审查副本。

用户加入组后应重新登录。检查服务、Socket 和日志：

```bash
systemctl status perflens-collector.service
ls -l /run/perflens/collector.sock
journalctl -u perflens-collector.service --since today
```

Collector journal 每行都是最多 2 KiB 的版本化 JSON 运维事件，不包含目标 PID、命令、
Profile 内容、perf stderr 或本地路径。需要关联客户端错误时，加 `-o cat` 查看
`request_id`、`error_id`、`error_code` 和 `stage`；完整字段说明见
[《故障排查》](troubleshooting.zh-CN.md#用结构化-collector-日志定位请求)。

普通用户可以用一条只读命令汇总检查这些状态：

```bash
perflens status --project /绝对路径/工作区
```

配置、Socket 和用户组前置检查通过后，该命令还会执行一次最长 500 毫秒的只读健康
握手，并用专用服务 UID 和内核 peer credentials 复核 Collector 身份；它不会运行 perf，
也不会写入 spool。Socket 文件仅仅存在不代表服务就绪。

Collector 的请求读取和采集时长是两个独立边界。每条换行分隔的 JSON 请求（包含换行符）
最多 64 KiB，而且必须在最多 5 秒内完整送达；`max_duration_seconds` 只能限制一次 perf
采集，不能放宽这项协议超时。未完成的慢连接会收到可恢复错误并被关闭，后续健康检查和
采集仍可继续。服务收到 `SIGTERM` 或 `SIGINT` 时会停止接受新连接、关闭监听器并删除
Socket；systemd 管理的正常停止不会因为遗留 Socket 被误判为仍然就绪。

每个已经接受的计划还会在固定 spool 中留下一个 `.perflens-consumed-plan-…` 隐藏墓碑。
它是 Collector 原子创建并同步到磁盘的 `0600` 零字节状态，不是性能产物；即使 perf
失败或服务重启，同一计划也会被拒绝。Collector 会在后续请求中回收超过
`max_plan_ttl_seconds` 的墓碑。`spool-status`、归档和清理命令会验证后跳过合法墓碑，
不把它计入产物数量/字节；任何内容、权限、属主或链接异常都会显示不安全并拒绝操作。
不要手工编辑或删除这些文件，需要重试时应由 MCP 生成一个新计划。

`collector.toml` 的 `policy_version = 1` 用于未来安全升级；缺失时兼容读取为版本 1，
不支持的版本会在部署和服务启动前拒绝。

正式策略默认位于 `/etc/perflens/collector.toml`。保持 `allow_other_target_uids = false`，先只开放 `stat` 和 `record`，并保持短时长、低频率和固定 spool。

长期自动采集还应检查三个累计存储边界：`max_spool_bytes` 限制全部产物的总逻辑
字节数，`max_spool_artifacts` 限制文件数量，`min_free_bytes` 为 spool 所在文件系统
保留空闲空间。默认分别为 10 GiB、1000 个文件和 1 GiB。Collector 会按本次计划的
最坏输出大小预留空间；任何边界不足时都在启动 perf 前返回
`RESOURCE_LIMIT_EXCEEDED`。PerfLens 不会自动删除、覆盖或轮转旧证据，管理员应先审查、
归档，再明确删除不再需要的产物。

日常不需要手工组合 `find`、`du` 和 `df`。已授权用户或管理员只运行下面一条只读
命令，即可看到中文状态、文件数、逻辑大小、磁盘空闲余量以及当前单次最多还能采集
多少数据：

```bash
perflens-admin spool-status
```

默认读取 `/etc/perflens/collector.toml`，不写配置、不修改或删除产物，也不启动采集。
`正常` 表示仍可容纳策略允许的最大单次产物；`接近边界` 表示使用率已达到 80% 或
最大单次产物已无法完整预留；`容量已耗尽` 会导致新采集被拒绝；`目录中存在不安全
项目` 表示发现未托管文件、子目录、符号链接、其他非普通文件或被修改的重放墓碑，
应先停止 Collector 并人工审查。
需要机器可读、带 `schema_version` 的完整证据时使用：

```bash
perflens-admin spool-status --json
```

如果尚未使用默认系统路径，可显式传入 `--config /绝对路径/collector.toml`。命令只
扫描 spool 的直接子项，不跟随链接；达到文件数或字节配额后会提前停止，因此此时
`scan_complete` 为 `false`，已观察数值是下界而不是完整目录总量。

这是时点检查，不会替下一次采集预留空间；最终仍以 Collector 启动 perf 前的独立
配额复核为准，并发产生的新证据可能让后续采集被安全拒绝。

## 归档并安全清理旧证据

PerfLens 不按时间自动删除性能证据。需要释放 spool 空间时，管理员先在独立磁盘或
备份位置准备一个 root 管理、不可组写的目录；下面路径只是示例：

```bash
sudo install -d -o root -g perflens -m 0750 /srv/perflens-archives
```

先生成只读计划，再创建归档。默认只选择 7 天前的托管产物，同时保留最新 20 份，
单次最多归档 1000 份或 10 GiB：

```bash
sudo perflens-admin archive-spool \
  --output /srv/perflens-archives/perflens-2026-08-04.zip \
  --dry-run
sudo perflens-admin archive-spool \
  --output /srv/perflens-archives/perflens-2026-08-04.zip
```

`archive-spool` 只接受 Collector 生成的
`plan-<20位十六进制>.perf.data` 和 `.stat.csv` 普通文件。它拒绝链接、目录、临时文件、
未知文件、属主/权限异常和采集期间发生变化的文件。归档使用不压缩 ZIP，内含版本化
manifest、源 inode/大小/mtime 和逐文件 SHA-256；发布时拒绝覆盖已有路径。源文件全部
保留，`selection_truncated: true` 表示还有符合条件的证据未装入本次有界归档。
合法的计划墓碑会在验证后跳过并保留，不会写入 ZIP 或进入后续清理清单。

把 ZIP 复制到独立存储并确认备份策略后，先运行名字和行为都完全只读的归档验证：

```bash
sudo perflens-admin verify-spool-archive \
  --archive /srv/perflens-archives/perflens-2026-08-04.zip
sudo perflens-admin verify-spool-archive \
  --archive /srv/perflens-archives/perflens-2026-08-04.zip \
  --verify-sources
```

第一条验证 ZIP 结构、manifest 和归档内每个成员的大小与 SHA-256。第二条还核对 spool
中仍存在的原文件设备号、inode、大小、mtime、属主、权限和 SHA-256；已经不存在的原
文件只会计入“已经不存在”，不会让完整归档变成失败。两条命令都不会删除或修改文件；
自动化程序可加 `--json` 获取版本化结果。

确实需要释放空间时，再生成精确清理计划：

```bash
sudo perflens-admin prune-archived-spool \
  --archive /srv/perflens-archives/perflens-2026-08-04.zip \
  --dry-run
```

确认 JSON 中每个 `planned_artifact_names` 后，才显式授权清理：

```bash
sudo perflens-admin prune-archived-spool \
  --archive /srv/perflens-archives/perflens-2026-08-04.zip \
  --authorization I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE
```

清理器要求归档文件及父目录由 root 管理，然后重新验证 ZIP 结构、manifest、归档内
数据哈希，以及 spool 原文件的设备号、inode、大小、mtime、属主、权限和 SHA-256。
所有仍存在的源文件都通过预检后才开始删除，删除前逐个再次复核；归档永不被删除。
重复执行是幂等的，已不存在的原文件只计入 `already_absent_artifact_count`。

这是人工管理员生命周期，不应交给 Agent 定时执行，也不应做成安装后自动轮转。若
spool 中出现未知项目，先停止 Collector 并人工审查，不能通过放宽名称或链接检查绕过。

## 一条命令安全更新策略

需要调整采集模式、最大时长、频率、事件或存储配额时，不要直接编辑正在使用的
`/etc/perflens/collector.toml`。先复制成独立候选文件，以普通用户编辑并收紧权限：

```bash
cp /etc/perflens/collector.toml ./collector.next.toml
chmod 600 ./collector.next.toml
# 使用你熟悉的编辑器修改带中英文注释的参数
perflens-admin update-policy --config "$PWD/collector.next.toml" --dry-run
```

确认版本化 JSON 中的哈希、`allowed_modes` 和计划命令后，只需管理员执行：

```bash
sudo perflens-admin update-policy --config "$PWD/collector.next.toml"
```

命令会严格解析候选 TOML，原子替换固定策略，重启一次 Collector，并通过内核 peer
凭据完成健康握手。候选内容与当前策略逐字节相同时返回 `unchanged`，不会要求 root、
写文件或重启。重启或健康检查失败时会恢复原配置，再重启并验证旧配置；如果恢复本身
失败则返回稳定错误，要求管理员人工检查。

此入口只用于参数调整：不允许改变唯一授权 UID 或固定 spool，也不会修改 service
unit、历史产物、用户/组、sysctl 或 capability。候选文件中的中英文注释会原样保留。
若确实需要迁移用户身份或存储目录，应作为单独的停机管理员流程处理，不能借
`update-policy` 绕过隔离边界。

## 内核权限

先运行：

```bash
perflens doctor
cat /proc/sys/kernel/perf_event_paranoid
```

Debian 的 `perf_event_paranoid=3` 可能在 CAP_PERFMON 正常检查前拒绝采集。管理员需要根据主机威胁模型决定是否调到兼容专用 Collector 的等级，并通过真实短时采集确认。

PerfLens 安装和运行时不会自动修改 sysctl、文件 capability 或 systemd 状态。不要为了省事让 MCP/Agent 以 root 运行，也不要默认给 Collector `CAP_SYS_ADMIN`。

## 真实 Collector 一键验收

重新登录后，以普通用户执行一条命令即可，不需要查找或输入 PID：

```bash
perflens accept-collector --authorize-host-acceptance
```

PerfLens 会以当前普通用户启动一个固定、隔离、最长约 30 秒的内置 CPU 测试负载，
通过 Collector 对它执行默认 1 秒、最多 5 秒的真实 `perf stat`，完成后无论成功失败
都会终止测试进程。Collector 仍然只接收绑定 PID、UID 和启动时间的短期单次计划，
不会收到任意命令、环境变量或输出路径。

成功时默认输出中文验收摘要，直接显示证据路径、SHA-256、指标数量，并明确说明它只
证明本机当前配置。指标产物写入策略限定的 `/var/lib/perflens`。自动化程序加 `--json`
获取带 `schema_version` 和 `status: passed` 的完整结果；需要留档时使用
`--output ./perflens-collector-acceptance.json`，且输出必须是新文件。失败时会返回稳定
错误，例如 Socket 权限、策略拒绝或内核禁止 perf。若所有事件都显示不支持或未计数，
验收也会失败；至少需要一个有限数值的 `measured` 指标才会显示“通过”。

这是主动采集，不是只读健康检查，所以必须显式传入授权开关。高级用户若要验证自己
已有且明确授权的进程，仍可使用 `perflens verify-collector --help`，该命令要求 PID
和两层附加授权。成功时默认显示中文证据摘要；自动化读取完整 Collection Artifact 时
添加 `--json`，需要留档时使用 `--output <尚不存在的文件.json>`。

## MCP 产品配置

Collector 验收成功后，再为 MCP 启用自动采集：

```bash
perflens-mcp \
  --allowed-root /绝对路径/工作区 \
  --allowed-root /var/lib/perflens \
  --artifact-root /绝对路径/工作区/perflens-results \
  --allow-writes \
  --allow-process-execution \
  --allow-active-collection \
  --allow-pid-attach \
  --allow-automatic-collection \
  --allow-project-execution \
  --collector-socket /run/perflens/collector.sock \
  --automatic-mode stat \
  --automatic-mode record \
  --automatic-max-duration-seconds 30
```

MCP 参数是第一层授权，Collector TOML 是独立的第二层授权。Skill 只能在两层都允许的范围内选择采集顺序。

完成配置后，用户可以用自然语言请求，不需要手工查 PID：

```text
使用 $perflens-performance-analysis 优化当前项目的运行性能。
允许运行我确认的项目可执行文件并采集最多 10 秒，不要附加其他已有进程。
```

Skill 必须先确认精确的项目根目录、可执行文件、参数和代表性工作负载。
PerfLens 以普通用户启动该文件并取得新 PID；Collector 只收到 PID 计划，不会收到项目
命令、环境变量或任意输出路径。用户要求“优化项目”不是无限执行授权。

## 升级和卸载

升级时先安装新 wheel/系统包。安装包只替换程序，不启动服务，也不覆盖管理员维护的
`/etc/perflens/collector.toml`。然后先只读预检：

```bash
sudo perflens-admin upgrade --dry-run
```

结果中的 `previous_service_sha256` 与 `candidate_service_sha256` 用于确认 unit 是否变化；
`service_update_required: false` 仍是正常情况，因为服务仍需重启来加载新程序。确认后只需：

```bash
sudo perflens-admin upgrade
```

`upgrade` 只读取固定的已部署策略，只更新带 PerfLens 托管标记且所有者、权限可信的
systemd unit，再执行固定的 `daemon-reload` 和 `restart`。它不会接受项目目录中的替代
策略，不修改 sysctl/capability，也不删除配置或 `/var/lib/perflens` 证据。若更新 unit
后重启或健康协议握手失败，会尝试原子恢复旧 unit 并重新加载；此时应按错误提示检查
`systemctl status` 和日志。升级成功后，再以普通用户运行一次：

```bash
perflens accept-collector --authorize-host-acceptance
```

软件卸载前，普通用户先对每个已接入项目运行 `perflens detach --project <项目>
--dry-run`，确认后去掉 `--dry-run`。它移除经过验证的 Codex/Claude 项目 MCP 接入和
未修改托管 Skill，但保留引导与性能证据，也不会代替系统服务卸载。然后由管理员执行：

```bash
sudo perflens-admin undeploy --dry-run
sudo perflens-admin undeploy
```

该命令只停用并删除经过管理标记、所有者和权限校验的 PerfLens unit，不删除
`/etc/perflens/collector.toml`、`/var/lib/perflens`、系统用户或组。之后再卸载
DEB 或 `/opt/perflens` 运行环境。性能数据只有管理员明确确认后才能删除。

## 面向其他用户的正式发行

正式产品已经提供两个 DEB：

- `perflens`：普通用户 CLI、MCP、Skill 和离线锁定运行依赖；
- `perflens-collector`：可选管理员与 Collector 入口，依赖完全同版本主包。

DEB 满足以下边界，未来 RPM 也应保持一致：

- 不联网下载 Python 依赖，依赖随包提供或由发行版解决；
- 不静默修改 `perf_event_paranoid`；
- 不自动授予 `CAP_SYS_ADMIN`；
- 安装软件包时不生成管理员配置、不启动服务；
- 部署后采用经管理员审查的最小模式和短时限；
- 提示管理员把明确的普通用户加入组并配置 `allowed_uids`；
- 提供无需手工 PID 的 `accept-collector` 作为安装后显式真实验收，而不是声称服务启动就等于 perf 可用。

容器部署时，Collector 应留在宿主机，只把受控 Unix Socket 提供给普通用户 MCP；不要把整个分析容器改成 `--privileged`。
