# 自研与复用决策

简体中文 | [English](dependency-decisions.md)

## 里程碑 0～5

| 能力 | 决策 | 原因与边界 |
|---|---|---|
| 边界验证和 JSON Schema | 复用 Pydantic 2 | 验证和 Schema 行为成熟。只由 `perflens.contracts` 导入，不进入解析或聚合热路径。MIT；可在 Contract Mapper 处替换。 |
| CLI | 复用 Typer | 提供稳定的类型化 CLI 和帮助生成。限制在 `perflens.cli`；Application Service 不依赖它。MIT。 |
| 打包 | 复用 Hatchling | 基于标准的 PEP 517 构建，配置面较小。只在构建时使用。MIT。 |
| Folded 解析 | 自研薄 Adapter | 标准本身是简单的按行交换语法。引入渲染器会增加无关代码；PerfLens 不会重新实现 FlameGraph 布局或渲染。 |
| 热点聚合 | 自研 | Self/Inclusive 语义、确定性 ID、资源上限和证据导向输出属于 PerfLens 领域逻辑。 |
| JSON 序列化 | 复用 Python 标准库 | 确定性的 `sort_keys` 输出不需要额外运行依赖。 |
| 测试 | 复用 pytest 和 Hypothesis | 成熟的示例测试和属性测试工具。仅开发环境使用。 |
| 代码规范、类型和安全 | 复用 Ruff、Pyright、pip-audit | 成熟、可替换的开发工具，Core 不导入它们。 |
| ELF 元数据 | 复用 pyelftools | 读取 ELF Header、Note、Section、Build ID 和 Debug Link。PerfLens 不实现 ELF/DWARF 解析。 |
| 地址符号化 | 复用 LLVM symbolizer / addr2line | 长驻 Provider 进程负责 DWARF、名称还原和内联展开。PerfLens 只负责有界协议适配和缓存。 |
| 规则文档 | 复用 PyYAML safe loader | 规则是数据；正则编译前会先验证为严格类型化的边界模型。 |
| Markdown 报告 | 复用 Jinja2 | 确定性的安装包内置模板负责渲染证据，不进行推理。 |
| MCP 协议 | 复用官方 MCP Python SDK 2.x | MCP 位于 Analysis Core 之外，暴露类型化的本地 stdio 工具。 |
| Benchmark 格式 | 自研薄 Adapter | 把文档化的 pyperf、Google Benchmark 和 hyperfine JSON 规范化为一个带版本 Contract；不自研 Benchmark Runner。 |
| 统计比较 | 自研保守的标准库实现 | 重复均值使用明确标注为近似值的正态区间，并结合实际影响和可比性检查；结果仍然只是候选。 |
| 主动采集 | 复用系统 perf | 薄且默认关闭的封装覆盖 record/stat/sched/lock/tracepoint。PerfLens 负责授权、资源边界、诊断和不可变输出，不重新实现内核探针。 |

没有复制任何第三方实现。运行依赖设置了版本范围，并锁定在 `uv.lock`。修改支持的依赖
范围前，依赖升级必须先通过 Schema 测试和 Golden 测试。
