# 产物 Schema 兼容与迁移

简体中文 | [English](schema-migrations.md)

PerfLens 产物使用语义化 Schema 版本：

- Patch 变更只澄清文档，或者放宽兼容性验证；
- Minor 变更新增可选字段，并且必须增加旧产物兼容测试；
- Major 变更会改变语义，必须提供明确的迁移工具。

Schema `1.0` 没有前置版本。读取器会拒绝不支持的 Major 版本。确定性字段和聚合语义会
参与分析指纹计算；改变这些内容会使缓存输出失效。

运行状态 Schema `1.0` 可以包含可选的 Collector 健康状态、服务身份、策略版本、允许
模式和 spool 字段。读取握手功能加入前生成的旧状态产物时，这些字段使用兼容默认值。

引导产物 Schema `1.0` 可以包含可选的 Codex/Claude 项目配置路径、安装状态和项目
Skill 内容指纹。旧产物缺少指纹时按“没有记录 Skill 所有权”兼容读取。

项目接入移除结果使用独立的 `ProjectDetachmentArtifact` Schema `1.0`，可以记录所选
客户端、Skill 移除策略、Codex/Claude 配置与 Skill 状态、实际移除路径和明确保留路径。
旧产物默认按原有“只处理 Codex、保留 Skill”语义兼容读取。

Collector TOML 策略使用独立的整数 `policy_version`。当前生成的策略写入版本 `1`；为了
兼容旧策略，缺失该字段时按版本 1 读取，而不支持的版本会在部署或 Collector 启动前
被拒绝。未来的策略变更必须在部署边界和 Collector 边界同时增加兼容测试及拒绝测试。
