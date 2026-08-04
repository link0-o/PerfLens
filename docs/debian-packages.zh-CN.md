# PerfLens Debian 安装包

简体中文 | [English](debian-packages.md)

PerfLens 为 Debian 13 `amd64` 提供两个职责分离的原生安装包：

- `perflens_<版本>-1_amd64.deb`：普通用户 CLI、MCP Server、Skill 和锁定运行依赖；
- `perflens-collector_<版本>-1_all.deb`：可选的 `perflens-admin` 与
  `perflens-collector` 入口和部署示例，依赖同版本主包。

只分析已有 Profile、不需要自动采集时，只安装主包：

```bash
sudo apt install ./perflens_0.1.0-1_amd64.deb
perflens setup --project /绝对路径/你的项目
```

需要自动采集时，同时安装两个包：

```bash
sudo apt install \
  ./perflens_0.1.0-1_amd64.deb \
  ./perflens-collector_0.1.0-1_all.deb

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

重新登录后运行：

```bash
perflens status --project /绝对路径/你的项目
```

## 升级与卸载

使用 `sudo apt install ./新版本.deb` 升级。系统包不会覆盖管理员策略。

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
