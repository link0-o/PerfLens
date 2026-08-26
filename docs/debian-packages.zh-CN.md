# PerfLens Debian 安装包

简体中文 | [English](debian-packages.md)

PerfLens 为 Debian 13 `amd64` 提供两个职责分离的原生安装包：

- `perflens_<版本>-<Debian修订号>_amd64.deb`：普通用户 CLI、MCP Server、Skill、锁定运行依赖
  和固定的非特权 Container Gate；
- `perflens-collector_<版本>-<Debian修订号>_amd64.deb`：可选的 `perflens-admin`、
  `perflens-collector`、同架构 Rust Helper 和部署示例，依赖同版本主包。

包中的 `/usr/bin/perflens-mcp` 和 `/usr/bin/perflens-collector` 是指向私有运行时启动器
的 root 管理入口。引导与部署器会在验证入口、目标和父目录均可信后，把入口路径原样
写入 Codex 配置或 systemd；不会解析成无法识别命令身份的通用启动器路径，也拒绝可写
目录中的符号链接。

只分析已有 Profile、不需要自动采集时，只安装主包：

```bash
sudo apt install ./perflens_0.3.2-1_amd64.deb
cd /绝对路径/你的项目
perflens init
```

需要自动采集时，同时安装两个包：

```bash
sudo apt install \
  ./perflens_0.3.2-1_amd64.deb \
  ./perflens-collector_0.3.2-1_amd64.deb

perflens setup \
  --project /绝对路径/你的项目 \
  --prepare-collector \
  --automatic-collection
```

`setup` 会验证 root 管理且不可写的系统包入口，然后自动把
`/usr/bin/perflens-collector` 写入 unit，并把 `/usr/bin/perflens-admin` 写入中英文
下一步指南，不需要用户判断安装布局或补传路径。如果只安装了主包却要求准备 Collector，
命令会在写文件前明确提示安装同版本 `perflens-collector` 包。显式
`--collector-command` 只用于受控的自定义安装布局。

安装两个 DEB 后，普通用户不再需要先记忆项目资产路径。管理员可直接运行：

```bash
sudo perflens-admin setup
```

向导选择模式并生成同一套受限默认策略；安装包本身仍不会自动启用服务。后续可使用
`perflens-admin switch-mode` 安全切换，并在项目运行 `perflens init --update` 同步 MCP。
详见[《Collector 权限模式选择与切换》](collector-mode-lifecycle.zh-CN.md)。

下面是需要项目内候选配置供审查时的高级流程。Debian 默认生成 `cap_perfmon` 非 root 模式；主机若保持
`perf_event_paranoid=3`，可以在首次生成资产时明确选择 Rust Helper：

```bash
perflens init --prepare-collector \
  --collector-privilege-mode paranoid3_helper
```

生成的中文指南会给出带 `--acknowledge-privileged-helper-risk` 的精确管理员命令；旧的
`--acknowledge-cap-sys-admin-risk` 名称仍兼容。该选择
不会让 Python Broker、MCP、Skill 或 Agent 变成 root，也不会自动修改 sysctl；只有
固定 Rust Helper unit 获得收窄后的 capability bounding set。

上一条 `0.2.0` 修复线保持上游版本不变，仅把 Debian 修订号从 `1` 增加到 `2`，因此已经安装
`0.3.2` 发布包把 Debian 修订号重置为 `1`；APT 会先比较上游版本 `0.3.2`，因此
它仍高于所有 `0.3.1-*` 安装包，而所有 PerfLens 命令显示 `0.3.2`。文件名只是示例，
应以实际下载文件为准。安装包不会自动启动服务、写入
`/etc/perflens`、修改 sysctl/capability 或授予用户权限。检查引导生成的双语
`collector.toml` 后，由管理员明确执行：

Docker 始终是可选外部运行时。两个包都不依赖或启动 Docker，不加入 Docker 用户组，
不写 daemon 配置，也不启用项目 Docker 策略。主包中的 Container Gate 默认不执行；只有
普通用户明确授权托管工作流时才使用。需要 Docker 的项目单独运行 `perflens init --docker`。

```bash
sudo perflens-admin deploy \
  --config /绝对路径/你的项目/perflens-setup/collector-assets/collector.toml
```

命令默认输出中文部署摘要，并明确区分“预检通过但尚未修改系统”和“部署完成且健康握手
通过”。自动化程序需要完整版本化部署结果时加 `--json`。

如果软件包升级会扩大 Helper capability 边界，应先运行
`sudo perflens-admin upgrade --dry-run` 检查 `helper_capability_expansion`。正式升级在没有
`--acknowledge-privileged-helper-risk` 时会在写 unit 和重启服务前拒绝。

重新登录后运行：

```bash
perflens status --project /绝对路径/你的项目
perflens-admin spool-status
```

第一条检查项目、MCP、Socket 和权限是否就绪；第二条用中文汇总 Collector 存储配额和
剩余空间。两条命令都只读。需要留存第二条命令的版本化 JSON 时加 `--json`。

后续调整采集时长、模式、事件或配额时，复制当前策略并编辑带中英文注释的候选文件，
不要直接改正在使用的文件：

```bash
cp /etc/perflens/collector.toml ./collector.next.toml
chmod 600 ./collector.next.toml
perflens-admin update-policy --config "$PWD/collector.next.toml" --dry-run
sudo perflens-admin update-policy --config "$PWD/collector.next.toml"
```

该命令会重启并验证服务，失败时恢复原策略；不会改变授权 UID、固定 spool、unit 或
历史产物。候选与当前配置相同时不写入也不重启。

长期运行后不要手工按日期删除 `/var/lib/perflens` 文件。先用管理员命令
`archive-spool --dry-run` 和 `archive-spool` 创建 root 管理、带 manifest 与 SHA-256 的
独立归档，再使用 `verify-spool-archive --verify-sources` 完全只读地核对两份证据，最后
运行 `prune-archived-spool --dry-run`。只有逐项确认计划后才传入
`I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE`。详细目录准备、默认保留量和完整命令见
[《产品部署指南》](deployment.zh-CN.md)。

## 升级与卸载

使用 `sudo apt install ./新版本.deb` 升级。系统包不会覆盖管理员策略，也不会自行重启
Collector。安装新版本后执行：

```bash
sudo perflens-admin upgrade --dry-run
sudo perflens-admin upgrade
perflens accept-collector --authorize-host-acceptance
```

前两条由管理员运行：先比较现有与新 unit，再安全更新并重启；配置和历史产物保持
不变，失败时尝试恢复旧 unit。最后一条由普通用户运行，确认新版本在本机仍能完成真实
短时采集。不要用 `undeploy` 加 `deploy` 代替日常升级，也不要重新提交项目目录中的旧
策略覆盖 `/etc/perflens/collector.toml`。
每个仍需接入的项目可在检查新版本后运行一次 `perflens init --update`，安全刷新项目级
MCP 参数、引导和未修改 Skill；用户修改过或无法证明所有权的内容不会被覆盖。

卸载软件包前，普通用户先对每个接入项目执行 `perflens detach --project <项目>
--dry-run`，确认它只计划移除经过验证的 Codex/Claude MCP 和未修改 Skill 后去掉
`--dry-run`。引导目录、结果和系统 Collector 数据仍保留。然后让管理员入口验证并移除
PerfLens 托管的 unit：

```bash
sudo perflens-admin undeploy --dry-run
sudo perflens-admin undeploy
sudo apt remove perflens-collector perflens
```

`undeploy` 和软件包卸载都默认保留 `/etc/perflens/collector.toml`、
`/var/lib/perflens`、`perflens` 系统用户和组，避免误删策略、性能数据或破坏产物
归属。只有管理员确认不再需要后才应手工清理。

## 构建边界

主包包含由 `uv.lock` 加哈希锁定的 Python 依赖，安装时不联网。由于其中包含
Python 原生扩展，主包是架构和 Python ABI 相关的；当前正式目标是 Debian 13、
`amd64`、系统 Python 3.13。Collector 包包含目标架构的 Rust Helper，因此同样是
架构相关包，并且必须与完全相同 Debian 版本和架构的主包配套。

构建器固定文件时间和权限；同一 wheel、锁文件、系统 Python 与架构重复构建会
得到相同 SHA-256。发布流程还会提取两个 DEB，在临时目录执行完整包冒烟测试。
