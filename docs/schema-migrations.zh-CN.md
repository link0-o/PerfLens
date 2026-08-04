# 产物 Schema 兼容与迁移

简体中文 | [English](schema-migrations.md)

PerfLens 产物使用语义化 Schema 版本：

- Patch 变更只澄清文档，或者放宽兼容性验证；
- Minor 变更新增可选字段，并且必须增加旧产物兼容测试；
- Major 变更会改变语义，必须提供明确的迁移工具。

Schema `1.0` 没有前置版本。读取器会拒绝不支持的 Major 版本。确定性字段和聚合语义会
参与分析指纹计算；改变这些内容会使缓存输出失效。

Collector TOML 策略使用独立的整数 `policy_version`。当前生成的策略写入版本 `1`；为了
兼容旧策略，缺失该字段时按版本 1 读取，而不支持的版本会在部署或 Collector 启动前
被拒绝。未来的策略变更必须在部署边界和 Collector 边界同时增加兼容测试及拒绝测试。
