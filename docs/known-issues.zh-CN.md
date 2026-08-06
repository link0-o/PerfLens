# PerfLens 已知问题

简体中文 | [English](known-issues.md)

本文记录已经复现、具有明确边界和临时处理方法的问题，包括已经修复的问题。
不要通过降低部署器安全检查来规避问题；升级前仍可按对应版本的临时方法处理。

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
