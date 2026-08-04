# PerfLens 中文开发指南

本文面向需要维护、修改和发布 PerfLens 的开发者。日常使用请先阅读
[中文 README](../README.zh-CN.md)；MCP 和 Skill 配置见
[《MCP 与 Skill 使用指南》](mcp-and-skill.zh-CN.md)。

## 开发环境

基本要求：

- Linux；
- Python 3.12 或 3.13；
- [uv](https://docs.astral.sh/uv/)；
- 可选的系统工具：`perf`、`addr2line`、`gcc`；相关测试会在工具不可用时按设计处理。

在仓库根目录安装锁定的全部运行和开发依赖：

```bash
uv sync --all-groups --frozen
```

确认环境：

```bash
uv run python --version
uv run perflens --version
uv run perflens-mcp --version
```

不要默认使用 sudo。PerfLens 的只读分析、测试和构建都不需要 root。

## 目录结构

| 路径 | 用途 |
|---|---|
| `src/perflens/domain` | 轻量领域模型、错误和端口，不依赖 Pydantic 或 Typer |
| `src/perflens/profiles` | folded、perf script、perf.data 输入适配器 |
| `src/perflens/hotspots` | 确定性的热点和调用路径聚合 |
| `src/perflens/contracts` | 带版本的 Pydantic 公共产物模型 |
| `src/perflens/application` | 分析、比较、诊断和源码定位用例 |
| `src/perflens/integrations` | 有界、无 shell 的外部命令适配 |
| `src/perflens/symbols` | ELF 检查和源码符号化 Provider |
| `src/perflens/collection` | 默认关闭、必须授权的主动采集 |
| `src/perflens/mcp` | MCP Server、权限策略和产物存储 |
| `src/perflens/cli` | Typer CLI 边界 |
| `.agents/skills` | PerfLens Performance Analysis Skill |
| `schemas` | 从公共 Contract 生成并提交的 JSON Schema |
| `tests` | 单元、集成、安全、Golden、性能和包冒烟测试 |
| `scripts` | Schema 生成与发布产物准备脚本 |

更完整的依赖方向和安全边界见[《架构说明》](architecture.zh-CN.md)。

## 必须遵守的设计原则

- 确定性分析与 LLM 推理解耦；Core 不调用任何 LLM API。
- 不自研 Agent 框架，不在 MVP 中增加 Web UI。
- 不直接解析 `perf.data` 二进制；通过系统 `perf script` 适配。
- 外部工具必须经过 Adapter，禁止 `shell=True`。
- 所有用户路径都要规范化并做边界验证。
- 只读分析与进程执行工具分离；附加 PID 必须明确授权。
- 默认不需要 root，不自行调用 sudo，也不修改主机内核策略。
- 解析器必须流式处理，错误诊断和原始预览必须有上限。
- 永远不覆盖输入 Profile；主动采集也不覆盖既有输出。
- 公共产物必须包含 `schema_version`。
- 不针对测试夹具或预期符号写特殊分支。

## 日常质量检查

提交前至少运行：

```bash
uv run ruff check .
uv run pyright
uv run pytest --cov=perflens --cov-fail-under=85
```

当前 CI 会在 Python 3.12 和 3.13 上执行检查。不要因为总覆盖率通过就忽略新增代码；新增错误分支和安全边界应有对应回归测试。

需要验证完整发布包时运行：

```bash
uv build --no-sources
uv run --isolated --no-project \
  --with dist/perflens-0.1.1-py3-none-any.whl \
  tests/package_smoke.py
uv run --isolated --no-project \
  --with dist/perflens-0.1.1.tar.gz \
  tests/package_smoke.py
```

示例中的版本号需要替换为当前 `pyproject.toml` 版本。正式发布的完整步骤见
[《发布流程》](releasing.zh-CN.md)。

## 如何修改解析器

新增或修改 Profile 解析器时：

1. 在 `src/perflens/profiles` 中实现或调整 Adapter/Stream。
2. 使用 `ResourceLimits` 约束输入字节、行长、记录数、栈深和基数。
3. 对单条坏记录保留有限诊断；不能无限保存原始输入。
4. 在 `tests/fixtures` 增加真实格式夹具。
5. 在 `tests/golden` 增加或更新确定性 Golden 输出。
6. 同时测试正常输入、畸形输入、超限输入和超长单行。

不要为了通过 Golden 测试硬编码符号名或夹具路径。

## 如何修改公共产物和 Schema

公共模型位于 `src/perflens/contracts/artifacts.py`。模型变更后生成 Schema：

```bash
uv run python scripts/generate_schemas.py
uv run pytest tests/unit/test_contract_schemas.py
```

兼容性规则：

- Patch：只做文档澄清或放宽兼容验证；
- Minor：增加可选字段，并加入旧产物兼容测试；
- Major：改变语义，需要明确的迁移工具。

确定性字段或聚合语义变化还必须更新分析指纹，避免旧缓存被当成新结果。原始规则见
[《产物 Schema 兼容与迁移》](schema-migrations.zh-CN.md)。

## 如何新增 MCP 工具

1. 优先把确定性能力实现为 Application Service，不要把业务逻辑写进 MCP Handler。
2. 在 `src/perflens/mcp/server.py` 暴露带类型的输入和结构化输出。
3. 选择正确权限：只读、写产物、进程执行或主动采集。
4. 所有文件必须经过 `PathPolicy`；写入只能发生在配置的 artifact root。
5. 在 `tests/mcp` 增加 Schema、Annotation、权限拒绝和端到端测试。
6. 同步更新 MCP/Skill 中英文使用文档。

MCP 的开关只代表服务器允许某类操作；主动采集仍需要每次调用的精确授权短语，PID 附加还有独立开关。

## 如何修改外部工具调用

- 只允许绝对、规范化、可执行的程序路径。
- 参数必须以列表/元组传入，禁止通过 shell 拼接。
- 同时排空 stdout 和 stderr，限制字节数并设置超时。
- 超时或超限时终止整个子进程组。
- 返回稳定的 `PerfLensError`，不要把无限量 stderr 直接传给调用者。
- 新的外部工具必须放在独立 Adapter 中，并测试启动失败、非零退出、超时和输出洪泛。

## 测试类型

- `tests/unit`：确定性逻辑和边界条件；
- `tests/integration`：CLI、perf.data Adapter 等跨组件流程；
- `tests/mcp`：MCP Schema、权限和客户端/服务端流程；
- `tests/security`：路径穿越、覆盖保护、文件/目录 fsync、目录替换和原子写入故障注入；
- `tests/golden`：稳定、可审核的产物输出；
- `tests/performance`：不会因普通 CI 噪声频繁误报的性能烟雾线；
- `tests/package_smoke.py`：从 wheel/sdist 安装后的入口点与资源完整性。

## 依赖和安全审计

运行时依赖必须有兼容上限，并提交更新后的 `uv.lock`。更新依赖后运行：

```bash
uv export --locked --no-dev --no-emit-project \
  --format requirements.txt \
  --output-file build/runtime-requirements.txt
uv run pip-audit \
  --requirement build/runtime-requirements.txt \
  --no-deps --disable-pip --strict
```

为什么选择或自研某项能力，记录在[《自研与复用决策》](dependency-decisions.zh-CN.md)。
安全报告和默认权限见[《安全策略》](../SECURITY.zh-CN.md)。

## 如何维护 GitHub Actions

- 外部 Action 的 `uses:` 必须使用 40 位完整提交 SHA，旁边保留便于审查的版本注释；
- 只从 Action 官方仓库核对 Release 标签对应的提交，不使用第三方转述的哈希；
- 所有 checkout 都保持 `persist-credentials: false`；
- 普通 CI 和 Release 构建默认只有 `contents: read`；
- `contents: write` 只允许出现在不 checkout、不运行项目代码的最终发布任务；
- `id-token: write` 和 `attestations: write` 只允许出现在不 checkout、不含 `run:` 的
  Release 来源证明任务，最终发布任务必须依赖它成功；
- 上传产物必须在文件缺失时失败，并设置不超过 7 天的中间保留期；
- 修改工作流后运行 `uv run pytest tests/unit/test_workflow_security.py`。

固定 SHA 不会自动获得安全修复，因此 Dependabot 或维护者仍需定期审查官方新版本并
明确升级。不可变引用解决的是“运行内容被静默移动”，不是替代更新维护。

发布用 wheel 和 sdist 必须在同一源码提交时间戳下独立构建两次，再运行
`scripts/verify_python_reproducibility.py` 做逐字节比较。不要因为偶发差异跳过门禁；应先
检查归档时间戳、构建后端版本、文件遍历顺序和生成文件是否稳定。

## 提交与发布建议

- 一个提交只表达一个清楚目的，例如 `fix:`、`feat:`、`docs:`。
- 提交前保持 `git diff --check`、Ruff、Pyright 和 pytest 全绿。
- 面向用户的变化写入 `CHANGELOG.md` 的 `Unreleased`。
- 已发布标签和 PyPI 版本不可覆盖；修复应提升版本，例如从 `0.1.0` 发布 `0.1.1`。
- 只有发布提交进入 `main` 且 CI 通过后才创建带注释标签。

当前验证记录见[《发布就绪检查》](release-readiness.zh-CN.md)。
