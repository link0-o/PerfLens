# PerfLens Debian 安装包

简体中文 | [English](debian-packages.md)

PerfLens 为 Debian 13 `amd64` 提供两个职责分离的原生安装包：

- `perflens_<版本>-1_amd64.deb`：普通用户 CLI、MCP Server、Skill 和锁定运行依赖；
- `perflens-collector_<版本>-1_all.deb`：可选的 `perflens-admin` 与
  `perflens-collector` 入口和部署示例，依赖同版本主包。

包中的 `/usr/bin/perflens-mcp` 和 `/usr/bin/perflens-collector` 是指向私有运行时启动器
的 root 管理入口。引导与部署器会在验证入口、目标和父目录均可信后，把入口路径原样
写入 Codex 配置或 systemd；不会解析成无法识别命令身份的通用启动器路径，也拒绝可写
目录中的符号链接。

只分析已有 Profile、不需要自动采集时，只安装主包：

```bash
sudo apt install ./perflens_0.1.1-1_amd64.deb
perflens setup --project /绝对路径/你的项目
```

需要自动采集时，同时安装两个包：

```bash
sudo apt install \
  ./perflens_0.1.1-1_amd64.deb \
  ./perflens-collector_0.1.1-1_all.deb

perflens setup \
  --project /绝对路径/你的项目 \
  --prepare-collector \
  --automatic-collection
```

版本号只是示例，应替换为下载文件的实际版本。安装包不会自动启动服务、写入
`/etc/perflens`、修改 sysctl/capability 或授予用户权限。检查引导生成的双语
`collector.toml` 后，由管理员明确执行：

```bash
sudo perflens-admin deploy \
  --config /绝对路径/你的项目/perflens-setup/collector-assets/collector.toml
```

命令默认输出中文部署摘要，并明确区分“预检通过但尚未修改系统”和“部署完成且健康握手
通过”。自动化程序需要完整版本化部署结果时加 `--json`。

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

卸载 Collector 前，先让管理员入口验证并移除 PerfLens 托管的 unit：

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
`amd64`、系统 Python 3.13。Collector 包本身是 `Architecture: all`，但必须与
完全相同版本的主包配套。

构建器固定文件时间和权限；同一 wheel、锁文件、系统 Python 与架构重复构建会
得到相同 SHA-256。发布流程还会提取两个 DEB，在临时目录执行完整包冒烟测试。
