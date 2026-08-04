# 真实世界 Profile 验收记录

简体中文 | [English](real-world-acceptance.md)

最终验收使用上游项目提供的 Profile，而不是 PerfLens 自己生成的测试夹具。

## 数据来源

- 来源：[Brendan Gregg FlameGraph 的 Linux perf 示例 Profile](https://github.com/brendangregg/FlameGraph/blob/41fee1f99f9276008b7cd112fca19dc3ea84ac32/example-perf-stacks.txt.gz)
- 上游提交：`41fee1f99f9276008b7cd112fca19dc3ea84ac32`
- 压缩源文件 SHA-256：`ad0d2cb09dba33c492893e6010adcc4806431b8a351b31798b7a4a2deddab7e5`
- 上游转换器：同一提交中的 `stackcollapse-perf.pl --all`
- 转换器 SHA-256：`74faa47a29d8df07cb06731dfd8bb94dc4c165b9d811ac6b4c9449eea2ac25d8`
- 转换后 folded Profile SHA-256：`b1a9d70d4d5604815775225ba4200789964eaade3f9232dd7462e6e591710a0b`

仓库不会再分发外部 Profile 和转换器。固定提交链接和哈希可以让验收输入被独立复现，
同时避免把第三方数据放入安装包。

## 端到端流程

2026-07-30 的验收运行了：

```bash
perflens analyze-folded --input upstream.folded --output analysis.json
perflens classify --analysis analysis.json --output diagnosis.json
perflens report \
  --analysis analysis.json \
  --problem "Upstream Vert.x CPU profile acceptance" \
  --metric "sample weight distribution" \
  --output report.md
```

结果：

| 检查项 | 结果 |
|---|---:|
| 解析的 folded 记录 | 710 |
| 格式错误记录 | 0 |
| 样本总权重 | 1,315 |
| 输出热点 | 531 |
| 输出调用路径 | 710 |
| 分析状态 | `complete` |
| 诊断状态 | `partial` |

`partial` 诊断是有意保留的：folded 输入没有事件或源码行元数据，而且没有通用符号规则
能够以足够强的证据生成候选分类。报告保留了这些限制，没有编造根因。

输出 SHA-256：

- analysis：`f3c5da385a7785765fcd96424fea9d67433be7514cb7cd4ff8e80ee83e3980bd`
- diagnosis：`a50e04eeb9864be24de9442ddfa487d3ec2aabc61a0561f203ccfcfae2f97b3c`
- Markdown 报告：`99f01ff2719803cb41ab60f68fff5b6b7c45870a9a627f9b089519a2032f3a2e`

这证明 PerfLens 能处理并非作者提供的真实 Profile，同时仍把结论限制在直接证据允许的
范围内。它不等同于本机特权 Collector 的真实采样验收；后者仍需按
[《产品部署指南》](deployment.zh-CN.md)在管理员批准的主机上执行。
