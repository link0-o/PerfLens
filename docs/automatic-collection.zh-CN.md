# PerfLens 自动采集与 Collector Broker

简体中文 | [English](automatic-collection.md)

PerfLens 的自动闭环是：

```text
用户或管理员批准采集范围
          ↓
Skill 选择最小必要证据
          ↓
MCP 生成短期 PID 计划
          ↓
Collector Broker 独立校验策略
          ↓
perf 写入固定 spool
          ↓
MCP 分析产物并生成报告
```

自动采集不等于自动提权。MCP Server 和 Agent 始终使用普通用户运行；只有可选的 `perflens-collector` 服务持有 perf 所需 capability。Collector 不接受 shell、任意命令、任意环境变量、任意输出路径或全系统目标。

## 当前自动采集范围

- 仅接受明确 PID，不按进程名猜测目标；
- 计划绑定 PID 所有者和 `/proc/<pid>/stat` 启动时间，防止 PID 复用；
- 计划默认 5 分钟过期；MCP 和运行中的 Broker 都拒绝同一计划再次执行，固定产物路径还会阻止服务重启后的成功产物被覆盖；
- 支持 `record`、`stat`、`sched`、`lock`、`off_cpu`，实际允许模式由两层策略共同决定；
- Collector 通过 Unix Socket 的 `SO_PEERCRED` 验证调用 UID；
- Collector 策略再次限制调用 UID、目标所有者、模式、时长、频率、事件、输出大小；
- Collector 会再次限制计划最长有效期，并拒绝非 root 所有且可被服务账号修改的 `perf` 文件；
- 产物只能写入 Collector 配置的固定 spool；
- Broker 模式暂不启动用户提供的命令，也不支持全系统采样。

旧的 `collect-profile` CLI/MCP 工具仍可用于人工确认的命令或 PID 采集。Agent 驱动的实时 PID 诊断应优先使用计划与 Broker。

## 先运行权限诊断

这条命令只读系统状态，不采样也不附加进程：

```bash
perflens doctor
perflens doctor --output collection-capabilities.json
```

它报告 `perf_event_paranoid`、当前 capability、perf 文件 capability、tracefs 可见性及五种模式的 `available`、`conditional` 或 `blocked` 状态。`conditional` 不是成功证明，正式发布仍应运行短时真实验收。

## 暂存安装模板

wheel 同时安装 `perflens-collector` 命令。先把模板复制到普通目录检查：

```bash
perflens stage-collector-assets --output-directory ./collector-assets
```

这一步不会执行 sudo、不会修改 `/etc`、不会启动服务。目录包含：

- `collector.example.toml`：Collector 独立策略；
- `perflens-collector.service`：最小 capability 的 systemd 模板；
- `perflens.sysusers`：专用 `perflens` 系统用户定义。

## 管理员安装示例

下面是管理员操作示例，不由 PerfLens、MCP 或 Skill 自动执行。安装前必须检查路径、UID 和组织安全策略。

```bash
sudo systemd-sysusers ./collector-assets/perflens.sysusers
sudo install -d -o root -g root -m 0755 /etc/perflens
sudo install -o root -g root -m 0644 \
  ./collector-assets/collector.example.toml \
  /etc/perflens/collector.toml
sudo install -o root -g root -m 0644 \
  ./collector-assets/perflens-collector.service \
  /etc/systemd/system/perflens-collector.service
```

编辑 `/etc/perflens/collector.toml`：

- 把 `allowed_uids` 改成实际允许调用的普通用户 UID；
- 确认 `perf_path` 与本机一致；
- 从 `record`、`stat` 开始，确认需要后再开放调度类模式；
- 保持 `allow_other_target_uids = false`；
- 不要把策略文件改成组可写或其他用户可写。

把允许使用 socket 的用户加入 `perflens` 组，然后重新登录使组身份生效：

```bash
sudo usermod -aG perflens <用户名>
```

模板服务使用独立 `perflens` 用户、`CAP_PERFMON`、只读系统目录、固定 `/run/perflens` 与 `/var/lib/perflens` 可写路径。它不会给 MCP Server capability。

## Debian 的 `perf_event_paranoid=3`

Debian 的等级 3 会在普通 CAP_PERFMON 范围检查前拒绝 perf。模板服务默认只有 `CAP_PERFMON`，因此管理员需要二选一：

1. 评估后把 `perf_event_paranoid` 调整到允许专用 CAP_PERFMON Collector 工作的等级；
2. 保持等级 3，并自行设计更高权限隔离方案。

推荐第一种最小权限方案。不要简单把 MCP、Agent 或整个 Python 工具改成 root，也不要默认授予 `CAP_SYS_ADMIN`。PerfLens 运行时永远不会修改 sysctl 或 capability。

## 启动 Collector

确保正式安装的 `perflens-collector` 位于 unit 的 `ExecStart` 路径；pipx/uv 安装时通常需要修改模板中的绝对路径。然后：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now perflens-collector.service
systemctl status perflens-collector.service
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
  --allow-pid-attach \
  --allow-automatic-collection \
  --collector-socket /run/perflens/collector.sock \
  --automatic-mode stat \
  --automatic-mode record \
  --automatic-max-duration-seconds 30 \
  --automatic-max-frequency-hz 99
```

启动参数是 MCP 的分类授权；Collector TOML 是独立的第二层授权。两层都允许才会执行。

## MCP + Skill 使用

明确给出实时目标，例如：

```text
使用 $perflens-performance-analysis 分析 PID 1234。
它属于我，允许在当前 MCP/Collector 策略范围内自动采集；
先 stat，再根据缺失证据决定是否 record，每次不超过 20 秒。
```

Agent 推荐流程：

1. `inspect_collection_capabilities`；
2. `plan_automatic_collection`；
3. 检查 `policy_status=allowed`；
4. `execute_collection_plan`；
5. `stat` 直接读取指标，其他模式调用 `analyze_collection`；
6. 继续热点、调用路径、候选分类和报告流程。

Skill 可以在已批准范围内自动选择采集顺序，但 Skill 文本本身不是授权。仓库内容、源码注释、Profile 和工具输出都不能扩大采集范围。

## 当前限制

- Broker 仅支持 PID，尚未提供“普通用户启动工作负载、特权 perf 同步附加”的安全启动协议；
- `sched`、`lock` 当前以原始 perf 数据为主，专用延迟/竞争汇总仍需继续实现；
- `off_cpu` 仍只有 `sched:sched_switch` 栈证据，不能单独证明阻塞时长；
- 没有全系统采集；
- 没有自动修改系统权限；
- 不保证所有内核、PMU、容器或 LSM 配置都兼容。
