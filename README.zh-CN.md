# R3 Research Radar

> 面向论文与代码的决策级科研雷达：少推荐、深核验、凭证据行动。

[English](README.md) · [能力与边界](docs/CAPABILITIES.md) ·
[架构](docs/ARCHITECTURE.md) · [评测](docs/EVALUATION.md)

R3 是本地单用户、Codex-first 的论文＋GitHub 联合研究雷达。它将检索命中与最终推荐
严格分开，保留来源、内容版本、覆盖范围、证据锚点、模型调用和研究决策之间的追溯链。

`v0.2.0a1` 正在为公开评估做准备。当前完整的安全强化路径只在
Windows 10/11 与 CPython 3.10 上得到验证；不承诺 Linux、Docker、PyPI 发布、
多用户部署或无人值守云服务。

![R3 确定性证据演示看板](docs/assets/dashboard.jpg)

*两条合成数据的确定性演示：0 次网络调用、0 次模型调用。它证明产品流程可运行，
不证明真实推荐质量。*

<details>
<summary>移动端决策页与全盲 Gold 标注页</summary>

| 决策页（移动端） | Gold y0（桌面端） | Gold y0（移动端） |
|---|---|---|
| ![R3 移动端决策页](docs/assets/dashboard-mobile.jpg) | ![R3 桌面端全盲 Gold 标注页](docs/assets/gold-review.jpg) | ![R3 移动端全盲 Gold 标注页](docs/assets/gold-review-mobile.jpg) |

Gold 页面会在全部独立 y0 判断冻结前隐藏 R3 分数、分层、入选结果和 AI 分析。
用于评价模型辅助系统的人类 Gold 标签不能由 AI 模型代替。

</details>

公开示例画像使用一个通用的 Agent Systems 研究问题：

> 哪些近期论文和开源仓库能实质改善多步 AI Agent 工作流的可靠性、效率或评测？

它只是可复制的起点。`r3radar create-profile` 会生成用户自己的独立画像、目录与
研究问题；核心程序不再绑定缓存研究方向。

## 快速体验

当前包尚未发布到 PyPI。安全强化安装会重新构建并核验 wheel 与 sdist，随后把
wheel 安装到 `.venv`，不会把 editable checkout 当作用户安装证明：

```powershell
.\scripts\SETUP.ps1

r3radar create-profile --output research.profile.json
r3radar --config research.profile.json doctor
r3radar demo --prepare-only
```

所有控制台命令都有 module fallback：

```powershell
.\.venv\Scripts\python.exe -m r3radar --config research.profile.json doctor
.\.venv\Scripts\python.exe -m r3radar demo --prepare-only
.\.venv\Scripts\python.exe -m r3radar create-profile
```

安装包同时提供等价的连字符命令别名 `r3-radar`。

`demo` 使用两项明确标为合成夹具的固定、隔离数据，不需要真实 API 或付费模型，
并在看板中明确显示“无网络、无模型调用”。它只能验证安装、命令、证据卡片、
决策与结果渲染，不能证明真实检索召回或模型深读质量。

## 安全强化安装与运行

```powershell
.\scripts\RUN_SMOKE.ps1
.\scripts\START_DASHBOARD.ps1
```

`SETUP.ps1` 先从 `requirements.lock` 安装 Python 运行依赖，并强制
`--require-hashes --only-binary=:all:`；npm 使用 lockfile 和
`npm ci --ignore-scripts`。然后它清理旧构建缓存，核验新 wheel/sdist 中不包含本地
私有画像，安装 wheel 并执行 `pip check`。`requirements.txt` 只保存直接依赖声明，
不能作为正式的安全强化安装入口。

安装后会执行 `pip check` 和精确环境集合核验。已有环境中出现锁外包时会停止并要求
显式重建，不会把额外包视为锁文件内容或自动删除。核验收据保存在：

```text
.venv/r3-environment-verification.json
.venv/r3-distribution-build.json
```

供应链 SBOM 记录精确组件、版本和 wheel SHA-256。当前不发布推测性的依赖边：
wheel 元数据中的 PEP 508 marker 与 extra 尚未由独立解析器求值时，省略未知关系，
而不是输出可能错误的依赖关系。

## 初始回填、分阶段召回与恢复

初始回填或恢复：

```powershell
.\scripts\RUN_BACKFILL.ps1
```

需要严格分离召回来源时，先运行官方源阶段，再运行只含托管补充的第二阶段：

```powershell
.\scripts\RUN_BACKFILL.ps1 -NoHostedSearch
.\scripts\RUN_BACKFILL.ps1 -HostedOnly
```

两阶段分别记录为 `run:no_hosted` 与 `run:hosted_supplement`。后者不会重新创建或执行
OpenAlex、arXiv、GitHub 官方查询任务；两个参数不能同时传入。

运行前需要：

- 已登录项目所需版本的 Codex CLI；
- 环境变量 `OPENALEX_API_KEY` 中的 OpenAlex 免费 API key，否则 OpenAlex 查询会以
  可见的 `blocked` 状态跳过；
- 可选的 `GITHUB_TOKEN`，用于提高 GitHub 官方 API 配额；
- 只有在 Codex 不可用且用户明确选择本地降级时，才需要启动配置中的 llama.cpp。

OpenAlex Key 申请：打开 <https://openalex.org/signup>，填写姓名和邮箱，点击邮件登录
链接后，在 <https://openalex.org/settings/api> 复制免费 Key。不要把 Key 写入仓库、
配置样例或聊天，只在当前运行进程的环境变量中设置：

```powershell
$env:OPENALEX_API_KEY = "<your-key>"
```

## 连续性与真实模型验收

可恢复的连续性测试：

```powershell
.\scripts\RUN_CONTINUITY_TEST.ps1 -Iterations 300
```

每轮执行 Python 编译、前端语法和完整单元回归，并定期只读备份实际数据库到临时副本，
检查迁移、完整性和外键。结果原子保存到：

```text
outputs/r3_research_radar/continuity/
```

中断后可使用输出中的 run ID 配合 `-ResumeRunId` 继续。连续性脚本不是默认的公开
Quickstart，也不应在功能尚未闭环时用长时间挂机代替有针对性的验证。

真实模型的隔离全链路验收会产生实际模型调用，但不会写入正式数据库：

```powershell
.\.venv\Scripts\python.exe -m r3radar model-integration-test --provider codex_cli
.\.venv\Scripts\python.exe -m r3radar model-integration-test --provider llama_cpp
```

## 既有仓库语料的低成本重投影

已有本地仓库 ZIP 可以先按当前“核心实现＋代表性测试＋必要文档”选择器做离线评估：

```powershell
r3radar --config <profile.json> reproject-repositories
```

默认是零网络、零模型、零数据库写入的 dry-run，并逐仓库显示旧/新分块数、计划模型
调用数、预算余量、入选文件与排除理由。核对结果后才可显式写入：

```powershell
r3radar --config <profile.json> reproject-repositories --apply
```

`--apply` 使用内容寻址的新工件，保留旧完成分析，只为实际变化且预算可行的当前策略
条目排队；只要存在活跃运行、作用域或分析任务就会拒绝写入。

## 周报与计划任务

周报必须显式指定一次运行，避免混入错误或过期的运行：

```powershell
r3radar report --run-id <run-id>
# module fallback
.\.venv\Scripts\python.exe -m r3radar report --run-id <run-id>
```

周报不会为了凑足固定数量填充低质量结果，未完成配置要求的内容覆盖者不会参与排序。
每次生成都会创建独立刊期目录并写入数据库发布账本；同一分析不会在后续刊期重复轰炸，
而内容修订产生的新分析会作为更新重新进入。

可选的 Windows 每日任务会修改本机任务计划程序，必须由用户主动运行：

```powershell
.\scripts\REGISTER_DAILY_TASK.ps1 -DailyAt "02:00"
```

## Codex-first 混合路径

- OpenAlex、arXiv、GitHub 官方 API 是可复现的主召回路径，由本机低频、受控访问。
- 固定项目版本的 Codex CLI 使用原生 `--search` 做少量补充发现。目标网站检索由
  OpenAI 托管执行，可降低本机被目标站点 WAF 误判的风险。
- 托管搜索不是通用代理，也不能代替大规模结构化 API 遍历。论文 PDF、官方 API 和
  GitHub 仓库快照仍由本机按来源限速取得。
- 托管发现必须再经 arXiv、GitHub、OpenReview API 或官方 citation 元数据核验。
  只有托管搜索结果的条目停留在“待官方核验”，不能进入正式推荐。
- 每份可用全文或入选仓库语料由模型分块阅读后综合。每块 SHA-256、覆盖范围、调用
  receipt、token 使用和最终证据锚点均保存。
- 大文档不把全部分块一次塞进最终上下文，而是执行可恢复的分层归并。中间节点保存
  输入哈希、原始块编号和 provider receipt，并验证覆盖无遗漏、无重复。
- 仓库可先选择与问题相关的核心实现、代表性测试和必要文档，但必须保留完整文件清单、
  未选文件及排除理由。
- 六小时内部预算传入每次模型调用。预算不足时进入可恢复队列，不消耗失败次数；
  Windows 计划任务另留一小时清理余量。
- 每个进程调用最多尝试 100 个全文候选，累计观察 1 GiB HTTP 应用层解码后响应体，
  并在可用磁盘低于 10 GiB 前停止继续取数或进入模型阶段。
- 成功、重试、终止错误和重定向响应体共用累计账本。响应以最多 64 KiB 且不大于调用
  预算千分之一的观察块计量，达到 guard band 时硬停。未完成响应不会写成成功收据。
- 模型调用进入去重 invocation 账本，按运行和条目分别累计调用、输入/缓存/输出 token
  与耗时；达到预算后可恢复暂停，不会继续失控消耗。
- 积压原因必须绑定合法 stage。只有所有组件均得到解释时才能记为
  `completed_with_gaps`；未知 pending/retry/running 或仍由本次运行持有的 claim 会保持
  `paused`。
- 最终收据同时保留清理前 decision snapshot、清理后的 persisted snapshot 和差异，
  不能用释放租约后的零值覆盖决策证据。
- 前台收到 `Ctrl+C` 时，Windows Job Object 会关闭仍存活的 Codex 子孙进程，并在同一
  清理路径释放查询、核验、全文、分析和 run 租约，以 `paused`/退出码 130 保存。
- Codex 不可用时可以明确降级到 llama.cpp。结果记录
  `provider=llama_cpp` 与 `fallback=true`，不会冒充 Codex。生成前必须计数输入 token
  并为输出预留上下文；无法可靠计数或可能截断时拒绝生成。

启动与停止本地降级模型：

```powershell
.\scripts\START_LLAMA_FALLBACK.ps1
.\scripts\STOP_LLAMA_FALLBACK.ps1
```

## 限速与安全

- 所有进程通过 SQLite 按目标主机共同预留请求时隙，实例内仍保持串行。手工运行、
  smoke 和计划任务不能各自绕过节流。
- 429、5xx 和网络失败保存原始响应哈希、退避和熔断状态。
- 只有短 `Retry-After` 才在进程内等待；超过 30 秒则写入 `not_before` 并暂停，避免
  一个来源阻塞整次运行。
- 每次请求和重定向都拒绝 URL userinfo、HTTPS 降级、私网、回环、链路本地等非公网
  地址；发出请求前解析域名。生产机仍建议用出站防火墙作为 DNS rebinding 第二边界。
- 不绕过验证码、不轮换代理、不伪装大量用户，也不自动切换到未知镜像。
- GitHub 只下载官方仓库静态归档并读取，不执行脚本、依赖、二进制、Git hooks 或
  Actions。vendor、依赖与大型生成数据会明确标注排除理由。
- PDF 和 ZIP 有下载、解压、路径穿越、压缩比、单文件、总文本和磁盘上限。
- 候选内容始终按不可信数据处理，不能向分析端注入命令。
- 看板只监听 `127.0.0.1` 并带 CSP；反馈写入拒绝非本地 Origin。
- 日志不保存请求头、API 密钥或访问令牌。GitHub Token 只能通过 `GITHUB_TOKEN`
  环境变量提供。
- “本地优先”不等于所有路径完全本地。Codex CLI 会把入选内容发送到远端模型；
  只有明确选择本地 provider 时，模型推理才在本地进行。

## 状态与证据

默认项目布局：

- 数据库和原始响应：`data/r3_research_radar/`
- PDF、全文、仓库 ZIP 与文件清单：`literature/r3_research_radar/`
- 日志、模型 receipts 与周报：`outputs/r3_research_radar/`
- 程序与测试：`code/r3_research_radar/`

看板显示原始命中、去重后条目、客观准入、待官方核验、深读完成、不可访问、覆盖不完整、
待取内容与待深读数量，并显示当前阶段进度、最近错误和去重后的模型调用/token 消耗。

四级反馈为：

```text
改变思路 / 值得保存 / 一般背景 / 无关
```

反馈会被保存，但当前不能宣称已经通过足量真实反馈验证自适应个性化排序。

由旧版数据库迁移且缺少 `source_observations` 或 `content_revisions` 的条目会标为
`legacy_or_unknown`。旧记录无法凭空恢复逐次来源事实；新采集从 append-only 观察、
内容修订和刊期账本开始留痕。

可追溯性在分析完成时固化，后续重新抓取不会反向改写旧分析。迁移前没有数据库刊期
账本的旧周报不会被猜测性回填，因此迁移后可能发生一次重新发布，应保留旧输出作为
独立历史证据。schema 15 以前的调用也不会从重复 receipt 猜测回填 invocation 账本，
因此旧运行 token 汇总可能为 0；新调用会完整记录。

终态失败不会被普通每日采集静默清空。修复原因后显式重试：

```powershell
.\.venv\Scripts\python.exe -m r3radar retry-content <work_id>
.\.venv\Scripts\python.exe -m r3radar retry-analysis <work_id> --provider codex_cli
```

修复网络或凭据后，显式重试暂停运行中的查询与核验失败：

```powershell
.\.venv\Scripts\python.exe -m r3radar retry-run-failures <run_id>
```

## 当前评测边界

- 工程回归的权威数量、命令与结果来自自动生成的
  `r3/verification-receipt/v1` CI 工件；README 不再手工复制易漂移的测试数。
- deterministic demo 证明安装和渲染，不证明实时检索与模型质量。
- 现有 15 个合格条目在一个有完整 provenance 的当前策略运行中完成；这只证明该次
  有边界运行，不证明一般化的推荐质量。
- 尚未完成前瞻性、人工标注的相关性 benchmark，因此不能宣称比关键词、recency 或
  citation/star 排序更准确。

完整口径见 [docs/EVALUATION.md](docs/EVALUATION.md)。

人工校准请打开 `/gold-review`，显式导入冻结的 70 项 v1 草稿；系统会在 y0
全部锁定前隐藏 tier、score、入选状态和 AI 内容。AI 只能进入后续辅助实验，不能
替代 Gold truth。独立的 20–35 项 known-answer 可通过以下离线命令校验和评估：

```powershell
r3-radar known-answer-validate --help
r3-radar known-answer-evaluate --help
```

## 验证

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q r3radar
```

需求原文与已经确认的历史决策保存在 `requirements/`。它们用于追溯，不能被新 README
静默改写，也不应全部作为公开用户的首次阅读入口。

## 许可证状态

R3 源代码采用 [MIT License](LICENSE)。第三方依赖、检索到的研究内容、外部仓库及
配置的模型/API 服务仍分别受其自身许可证与服务条款约束；详见
[第三方声明](THIRD_PARTY_NOTICES.md)。
