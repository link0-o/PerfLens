# PerfLens 产品部署指南

简体中文 | [English](deployment.md)

PerfLens 应拆成普通用户分析端和系统 Collector 两部分部署：

```text
普通用户：perflens + perflens-mcp + Skill
                       │ Unix Socket
系统服务：专用 perflens 用户 + perflens-collector + CAP_PERFMON
```

管理员只负责首次安装、策略和主机权限。日常 Agent、MCP 和分析命令不使用 sudo，也不持有 perf capability。

## 从当前 wheel 部署

以下流程适合开发验收和还没有 DEB/RPM 的版本。先在源码目录构建：

```bash
.venv/bin/python -m build
```

把 Collector 安装到系统可执行、但不在用户家目录中的独立环境：

```bash
sudo python3 -m venv /opt/perflens
sudo /opt/perflens/bin/python -m pip install \
  ./dist/perflens-0.1.0-py3-none-any.whl
```

这里的版本号只是示例，应替换为实际构建版本。正式离线部署应同时提供 wheelhouse 或完整系统包，不应在安装脚本中隐式访问网络。

普通用户首次安装和项目配置应先按照[《安装与首次使用》](../INSTALL.zh-CN.md)运行 `perflens setup`。本页主要面向需要部署系统 Collector 的管理员。

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

多个被授权用户需要重复传入 `--allowed-uid`。该命令只生成可检查文件，不执行 sudo、不写 `/etc`、不启动服务。

## 管理员安装

先检查生成的 TOML 和 systemd unit，然后安装：

```bash
sudo systemd-sysusers ./collector-assets/perflens.sysusers
sudo install -d -o root -g root -m 0755 /etc/perflens
sudo install -o root -g root -m 0644 \
  ./collector-assets/collector.example.toml \
  /etc/perflens/collector.toml
sudo install -o root -g root -m 0644 \
  ./collector-assets/perflens-collector.service \
  /etc/systemd/system/perflens-collector.service
sudo usermod -aG perflens <用户名>
sudo systemctl daemon-reload
sudo systemctl enable --now perflens-collector.service
```

用户加入组后应重新登录。检查服务、Socket 和日志：

```bash
systemctl status perflens-collector.service
ls -l /run/perflens/collector.sock
journalctl -u perflens-collector.service --since today
```

正式策略默认位于 `/etc/perflens/collector.toml`。保持 `allow_other_target_uids = false`，先只开放 `stat` 和 `record`，并保持短时长、低频率和固定 spool。

## 内核权限

先运行：

```bash
perflens doctor
cat /proc/sys/kernel/perf_event_paranoid
```

Debian 的 `perf_event_paranoid=3` 可能在 CAP_PERFMON 正常检查前拒绝采集。管理员需要根据主机威胁模型决定是否调到兼容专用 Collector 的等级，并通过真实短时采集确认。

PerfLens 安装和运行时不会自动修改 sysctl、文件 capability 或 systemd 状态。不要为了省事让 MCP/Agent 以 root 运行，也不要默认给 Collector `CAP_SYS_ADMIN`。

## 真实 Collector 验收

选择当前用户拥有、允许短时观察的测试 PID。例如先启动一个临时进程：

```bash
sleep 30 &
test_pid=$!
```

使用普通用户执行一次最多 5 秒的真实 `perf stat`：

```bash
perflens verify-collector \
  --socket /run/perflens/collector.sock \
  --pid "$test_pid" \
  --duration-seconds 1 \
  --authorize-target \
  --authorization I_EXPLICITLY_AUTHORIZE_TARGET_PROFILING \
  --authorize-pid-attach \
  --pid-authorization I_EXPLICITLY_AUTHORIZE_PID_ATTACH
```

成功时输出带 `schema_version` 的 Collection JSON，指标产物写入策略限定的 `/var/lib/perflens`。失败时会返回稳定错误，例如 Socket 权限、策略拒绝、PID 所有者不符或内核禁止 perf。

这条命令是真实采集，不是只读健康检查；不要对未授权 PID 执行。

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
  --collector-socket /run/perflens/collector.sock \
  --automatic-mode stat \
  --automatic-mode record \
  --automatic-max-duration-seconds 30
```

MCP 参数是第一层授权，Collector TOML 是独立的第二层授权。Skill 只能在两层都允许的范围内选择采集顺序。

## 升级和卸载

升级时先安装新 wheel/系统包，再检查 unit 与策略差异，然后重启 Collector。不要覆盖管理员维护的 `/etc/perflens/collector.toml`。

卸载顺序应为：停止并禁用服务、移除 unit、卸载 `/opt/perflens` 运行环境。`/var/lib/perflens` 中可能包含性能数据，默认应保留；只有管理员明确确认后才能删除。系统用户和组也不应在仍有产物归属时自动删除。

## 面向其他用户的正式发行

正式产品建议提供两个包：

- `perflens`：普通用户 CLI、MCP、Skill，可通过 wheel/PyPI/pipx/uv 安装；
- `perflens-collector`：DEB/RPM，安装专用运行环境、sysusers、systemd unit 和默认策略。

DEB/RPM 的安装脚本应满足：

- 不联网下载 Python 依赖，依赖随包提供或由发行版解决；
- 不静默修改 `perf_event_paranoid`；
- 不自动授予 `CAP_SYS_ADMIN`；
- 首次安装生成配置，升级时保留管理员配置；
- 安装后服务仍默认采用最小模式和短时限；
- 提示管理员把明确的普通用户加入组并配置 `allowed_uids`；
- 提供 `verify-collector` 作为安装后的显式真实验收，而不是声称服务启动就等于 perf 可用。

容器部署时，Collector 应留在宿主机，只把受控 Unix Socket 提供给普通用户 MCP；不要把整个分析容器改成 `--privileged`。
