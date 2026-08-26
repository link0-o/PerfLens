# PerfLens 已知限制

简体中文 | [English](limitations.md)

folded 文本无法恢复该格式本身没有保存的进程、线程、CPU、事件、DSO、地址、时间戳或
源码信息。`perf script` 和 `perf.data` 可以保留这些字段，但完整程度取决于采集方式和
可用符号。未知信息会保持为未知。结果能够指出带权重的热点和调用路径，但不能单独
证明因果关系或实际耗时。

精确聚合有明确上限。超过配置的基数限制时，分析会返回可恢复的资源限制错误；不会
使用近似值，也不会静默截断精确数据。

PerfLens 把 `perf.data` 解码交给选定的系统 `perf`。Adapter 只读且有资源上限，但跨主机
Profile 仍可能需要匹配的 perf 版本、DSO、调试文件、Build ID 或挂载命名空间信息。
普通 MCP 进程在 `perf_event_paranoid=3` 下会被内核拒绝；这不等于已部署的 Collector
也不可用。当前 Debian 13 人工验收已证明 `paranoid3_helper` 能完成软件 `stat` 与
`cpu-clock record`，同时如实报告硬件 PMU 没有可用计数。自动化测试使用真实 Unix Socket
和可执行 perf Test Double 覆盖成功与拒绝路径。该证据不证明其他内核、虚拟机、PMU、
LSM 或高级 trace 模式可用。PerfLens 永远不会请求 sudo，也不会修改 perf 安全策略。

特权 Collector 只接受 PID 目标。对于已确认的当前项目工作负载，普通用户协调器可以
启动一个项目目录内的可执行文件，在内部取得 PID，然后提交同样的纯 PID 计划。
Collector 不会收到或启动该命令。目前不支持交互式程序、任意环境变量、全系统采样，
以及没有前台运行模式的守护进程工作负载。Unix Socket 的计划、对等身份、策略和 spool
流程已经使用可执行 perf Test Double 完成集成测试；每台主机仍要求管理员批准配置，
并由普通授权用户执行一次真实验收。

源码符号化要求已验证的模块相对偏移，以及匹配的模块或调试文件。PerfLens 不会从运行
时地址猜测 PIE/ASLR 重定位。LLVM Provider 已在本地完成协议测试；已安装的 GNU
addr2line 后备也使用 PIE、共享库、Strip 和独立调试文件夹具进行了验证。

分类使用通用符号和 DSO 规则。规则匹配始终只是低或中置信度候选，绝不是已确认根因。
仅凭 on-CPU 数据无法确认等待时间、I/O 延迟、内存分配行为或某个优化方案的正确性。

Profile 比较描述所选事件的相对分布，不能证明绝对耗时发生回退。Benchmark 比较对重复
均值使用近似正态 95% 区间，同时检查实际影响阈值和环境可比性；没有工作负载匹配且
保持正确性的 A/B 证据时，不会声称优化已经验证成功。

发布版 `0.3.0` 正式支持 `stat` 和 `record`，并通过可选的 `full_diagnostics` 配置为
`sched`、`off_cpu`、`lock` 提供独立 Trace Helper、目标过滤、专用确定性分析和一致性验证。
即使验证通过，丢失、截断、边界缺失
或无法配对的证据仍必须报告 `partial`；futex 只能是用户态锁候选，缺少真实来源时不能
猜测 owner 或持锁时间。详见
[Collector 与用户态锁能力路线图](collector-capability-roadmap.zh-CN.md)。

发布版 v0.3.1 的 Docker 主动采集只覆盖本地 Linux Docker Engine、cgroup v2 和一个明确
进程。它不会自动扩大成整容器或多进程聚合、远程 Engine、Docker Desktop VM、Compose、
Kubernetes、自动 build/pull 镜像或任意 Docker 参数。已有容器会话绑定一个具体进程实例；
托管临时容器只使用本地不可变镜像和固定项目配方。cgroup 差值属于整个容器，不能写成
目标进程独占指标；无法保留已验证的容器 root/module 快照时，符号和源码证据必须标记为
`partial`。详见 [v0.3.1 Docker 指南](docker-container-roadmap.zh-CN.md)。C/C++、Java、
Python 和 Go 用户态锁 Adapter 仍计划进入 v0.4.0；公共合同骨架不代表 Adapter 当前可用。

发布版 v0.3.2 增加默认关闭的有界优化会话，可执行绑定 Recipe 的类型化 baseline/candidate
构建。Preview 不 build/pull，会话不接受任意 Docker 参数或源码路径；只有经过 Artifact
复核的匹配 A/B 才能声称 Verified Improvement。离线层只允许 `RUN --network=none`；管理员
联网层只允许 `none` 或 `default`。短生命周期容器可能在最终资源读取前失去 cgroup；此时
PerfLens 只保留最后一次已验证周期快照并标记为 partial 下界，不会声称资源转移证据完整。
人工可以明确选择保留未验证候选，但该处置不会改变 Iteration 结论。详见
[已知问题](known-issues.zh-CN.md)和
[v0.3.2 优化指南](docker-optimization-roadmap.zh-CN.md)。
