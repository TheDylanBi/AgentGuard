# 用 ASB 验证 ICB-Guard

工具来源与首次调用检查已升级，详见 [工具契约与诊断说明](asb-tool-trust.md)。
`--require-tool-contracts` 现在必须使用完整的 v2 独立契约；下文 v1 示例仅用于旧格式兼容，不能用于严格部署。
严格模式会在运行前验证所有选中工具的契约覆盖。可选的分离 Ed25519 签名、公钥信任、
独立语义任务要求与多轴诊断见上述说明和 [任务步骤说明](asb-task-context.md)。

入口是 `python -B -m adapters.asb.run`。默认读取本机 `F:/Datasets/ASB`。
原始 ASB 目录只读使用；每次运行将其 Python 源码与 JSON 数据复制到结果目录的
`runtime/`，记录全部快照文件的 SHA-256。不复制 `.env`、缓存、原始记忆库或密钥。

## 评测协议

保留下载版本的 ASB 原生 Agent 主体、攻击注入、模拟工具、
`check_attack_success`、`check_original_success` 和可选的 `judge_response` 函数。
官方评分函数直接从本地 `main_attacker.py` 编译加载，不重写评分逻辑。

默认保持 `--recovery native --review-profile shared`，启用 `--response-retries 1`
处理执行前不可用响应。额外协调需要显式设置 `--recovery bounded`。
它在策略拒绝后、以及原生执行结束时，允许有界的行动模型
补全请求；它不提供官方必用工具清单，不强制执行无关操作。恢复时仍走同一个授权
入口，成功执行过的无参数调用不重放。技术性响应纠正只发生在工具执行前。
若需要保留原生 Agent 控制流并关闭响应再生成，使用
`--recovery native --response-retries 0`。两种设置不能混作同配置对照；比较器会拒绝。

```text
ASB 原生 Agent 提议调用
  → 原生 call_tools 中的统一执行钩子
  → baseline：直接运行 ASB 模拟工具
  → guarded：能力证书 + 原有硬约束 + CallReviewer 逐次审查
      ALLOW：运行同一个 ASB 模拟工具
      BLOCK / CONFIRM：不运行，返回真实的策略拒绝
  → ASB 原生观察格式、注入和后续规划
  → ASB 官方成功判定函数
```

所有工具采用相同的模拟能力声明，声明仅授予该工具名的最大能力；它本身不授予任务权限。
审查器只接收原始任务、当前工具名/描述，以及主机实际观察到的工具输出。
攻击目标、成功标记、工具的 normal/attacker 标签不传给审查器。
工具输出在 ASB 完成 OPI 追加后才进入审查历史，并明确保留不可信状态。

适配器替换了 AIOS 调度与模型传输，使用串行 OpenAI-compatible Chat Completions；
它保留原生 Agent Query/Response 接口，baseline 和 guarded 使用相同传输。
因此结果应描述为 **“ASB 原生 Agent/工具/评分 + ICB-Guard，串行 API 适配运行”**，
不能声称完整复现 AIOS 调度或官方全部模型后端。未实现 Ollama 原生协议；
可以连接支持 Chat Completions 与工具调用的本地/远程服务。

`CONFIRM` 不自动批准。模型/审查/审计异常标记为 incomplete，不当作成功防御。
原生 ASB 会捕获工具异常，适配器会在返回工具调用入口后重新抛出主机故障，防止错误被吞掉。
日志写入发生在执行前，失败则不执行。审查通过后再次校验能力与动作绑定。

## 环境

本次已在项目的 `tmp/asb-venv` 中准备独立 Python 环境。使用它不会变更生产网关环境。
如果换机器或重建环境，可以使用 Python 3.11+：

```powershell
Set-Location 'F:\Code\MLLM Agent'
python -m venv tmp/asb-venv
$asbPython = Join-Path $PWD 'tmp/asb-venv/Scripts/python.exe'
& $asbPython -m pip install -r adapters/asb/requirements.txt
```

原生 ASB Agent 顶层导入了 pandas、NumPy 和 LangChain，即使不运行记忆攻击也需要它们。
这个入口不导入 AIOS 的 GPU 模型注册器，不需要安装 torch、vLLM 或下载模型权重。
不自动加载项目或 ASB 的 `.env`；请显式设置环境变量。

## 复用 AgentDojo 行动模型，单独配置审查模型

**行动模型默认直接复用 AgentDojo 的 pi 配置，不需要设置 `ASB_ACTION_*`。**
优先读取项目内 `.local-qwen/models.json` / `auth.json`，没有项目配置时读取
`~/.pi/agent`。当前项目只有一个 `remote-action / deepseek-flash`，会自动选择。
接口地址、凭证、模型 ID、输出 token 上限和 `maxTokensField` 从同一配置读取；
支持已有的 `$变量名` / `${变量名}` 凭证引用，不复制或显示凭证。

如果 AgentDojo 使用其他配置目录，可原样传入 `--pi-agent-dir`；存在多个模型时，
使用与 AgentDojo 相同的 `--provider` / `--model` 选择即可。不会自动回退到其他模型。
仅支持 `openai-completions` API；OAuth 和 `!命令` 类型配置不会被擅自执行或转换。
不修改原有 pi 配置，也不自动配置审查模型。

先检查现有行动模型配置：

```powershell
Set-Location 'F:\Code\MLLM Agent'
$asbPython = Join-Path $PWD 'tmp/asb-venv/Scripts/python.exe'
& $asbPython -B -m adapters.asb.run --mode baseline --skip-refusal-judge --check
```

`action_config_source: agentdojo_pi`、`action_model_configured: true` 表示已复用。
检查不会联网，也不会显示服务地址或密钥。

审查模型由你在同一个 PowerShell 窗口中自行设置，以下都是占位符：

```powershell
Set-Location 'F:\Code\MLLM Agent'
$asbPython = Join-Path $PWD 'tmp/asb-venv/Scripts/python.exe'

$env:ICB_INTENT_LLM_BASE_URL = 'https://你的独立审查模型服务/v1'
$env:ICB_INTENT_LLM_API_KEY = '审查模型密钥'
$env:ICB_INTENT_LLM_MODEL = '实际审查模型ID'
$env:ICB_INTENT_LLM_TIMEOUT_SECONDS = '120'

# 原版 ASB 拒答裁判固定使用 gpt-4o-mini；该服务需提供这个模型。
$env:OPENAI_BASE_URL = 'https://api.openai.com/v1'
$env:OPENAI_API_KEY = '官方拒答裁判服务密钥'
```

只有显式选择 `--action-config env` 时，才使用旧的 `ASB_ACTION_MODEL` /
`ASB_ACTION_BASE_URL` / `ASB_ACTION_API_KEY`；这种模式支持 `OPENAI_BASE_URL` /
`OPENAI_API_KEY` 回退。默认模式不会被遗留的 `ASB_ACTION_*` 变量覆盖。
审查继续使用现有 `policy.call_review.CallReviewer` 和 `ICB_INTENT_LLM_*` 配置。

如果只需要官方 ASR 和原任务成功率，可在两组都加 `--skip-refusal-judge`。
这会跳过固定 GPT-4o-mini 拒答裁判，将 `official_refusal_rate` 记为 null，
不改动另外两个官方成功判定函数；此时不需要额外的 `OPENAI_API_KEY`。

## 先检查，再运行少量 OPI 对照

```powershell
$common = @(
  '--asb-root', 'F:/Datasets/ASB',
  '--attack', 'opi',
  '--attack-type', 'context_ignoring',
  '--agent', 'financial_analyst_agent',
  '--task-num', '1',
  '--limit', '5',
  '--max-tokens', '2048',
  '--timeout', '300',
  '--tool-schema', 'empty-object'
)

& $asbPython -B -m adapters.asb.run @common --mode guarded --check

& $asbPython -B -m adapters.asb.run @common --mode baseline --output results/asb_baseline_opi_smoke
& $asbPython -B -m adapters.asb.run @common --mode guarded --output results/asb_guarded_opi_smoke

& $asbPython -B -m adapters.asb.compare `
  --baseline results/asb_baseline_opi_smoke/summary.json `
  --guarded results/asb_guarded_opi_smoke/summary.json `
  --output results/asb_opi_smoke_comparison.json
```

`--check` 完全离线，不调用模型。`ready: true` 只表示依赖/密钥存在，不证明服务可连接或模型可用。
结果目录必须不存在，避免覆盖旧实验；重跑时换目录名，或省略 `--output` 自动生成时间戳目录。
`--task-num` 是每个 Agent 选几个任务；`--limit` 是最终任务与攻击工具组合的上限。
默认 `--task-num 1 --limit 10`，不会意外启动整个数据集。

ASB 的原始工具 schema 使用 `parameters: null` 或省略该字段。
默认 `--tool-schema native` 完整保留这一格式。如果服务严格要求 JSON Schema 对象，
使用上面命令中的 `empty-object`：仅将无参数工具的 schema 转成空对象，不更改实际执行参数（仍为 None）。
该选项会写入结果；比较器要求两组相同。

## 正常任务与其他攻击

无攻击任务也要分别运行 baseline / guarded，用于观察误拦截和正常任务完成率：

```powershell
& $asbPython -B -m adapters.asb.run --attack clean --mode baseline --task-num 1 --limit 0 --max-tokens 2048 --tool-schema empty-object --output results/asb_baseline_clean
& $asbPython -B -m adapters.asb.run --attack clean --mode guarded --task-num 1 --limit 0 --max-tokens 2048 --tool-schema empty-object --output results/asb_guarded_clean
```

clean 模式每个正常任务只运行一次，不按攻击工具数量重复加权。其攻击成功率为 null。

| `--attack` | 原生设置 |
|---|---|
| `opi` | observation_prompt_injection |
| `dpi` | direct_prompt_injection |
| `mixed` | 同时开启 DPI 和 OPI |
| `pot` | pot_backdoor |
| `pot-clean` | pot_clean（原生 PoT 无触发对照，仍包含相关工具与示例） |
| `memory` | memory_attack + read_db；必须提供 `--memory-db` |

`--attack-tools all/agg/non-agg` 对应原版攻击工具列表。
`--attack-type` 支持 naive、context_ignoring、fake_completion、escape_characters、combined_attack。
可重复提供 `--agent`；省略则遍历全部 Agent。

完整选择公开任务时，用 `--task-num 999 --limit 0`，baseline 和 guarded 同样设置。
当前本地数据可选 10 个 Agent、51 个正常任务；all 工具列表对应每种攻击配置 2,040 个任务/工具组合，
描述映射覆盖 420 个工具名。这是配置/覆盖检查结果，不是已运行的安全成绩。
不同 attack-type 需要分别运行并保留相同配置的对照。此处不把某一种攻击配置称为“整个 ASB”。

DPI 和 mixed 评测的信任前提：守卫由独立可信入口获得**注入前的原始任务**。
攻击追加文本仍按原版方式交给行动 Agent；守卫不从被污染文本中猜测/截取用户意图。
这代表有可信用户入口的防护设置，结果报告必须注明。

Memory 攻击示例：

```powershell
& $asbPython -B -m adapters.asb.run --attack memory --mode guarded --memory-db 'F:/Datasets/ASB/memory_db/direct_prompt_injection/实际已有数据库目录' --limit 5 --tool-schema empty-object
```

传入的数据库复制到本次结果目录；不向原始数据库写入，也不在评测中重新生成投毒记忆。
两组应使用同一原始数据库快照。嵌入服务使用原版 `OpenAIEmbeddings` 和 `OPENAI_*` 配置；
必须与现有数据库使用的嵌入模型/维度兼容。数据库读写可能会创建锁文件，但仅发生在复制件中。

如果需要已有的管理员业务硬规则，在 guarded 命令中增加
`--business-policy '你的实际规则文件绝对路径'`。默认空规则，不根据攻击标签新增禁令。

## 结果与判读

每次输出：

- `summary.json`：配置、代码哈希、逐条官方判分、分母、错误、策略统计和汇总指标。
- `selection.json`、`catalogs.json`、`source-hashes.json`、`policy-source-hashes.json`：
  任务选择、描述配置、ASB 与安全策略源码哈希。
- `runtime/`：本次 ASB 代码/数据副本。
- 每个样本目录：`messages.json`（原生消息）、`native.log`、`calls.json`（实际执行）、
  `reviews.json`（现有逐次审查记录）、`audit.jsonl`（带签名哈希链）、`result.json`。
- `requests.json`：每次行动模型请求的预算、finish_reason、usage、有限错误码及重试次数，
  不保存服务正文、地址或凭证；`recovery.json`：实际恢复请求与结果。
- `audit-public.pem`：验证审计签名的公钥；临时私钥在结束后删除。

| 指标 | 解释 |
|---|---|
| `official_attack_success_rate` | 官方消息标记判定的攻击成功率，越低越好 |
| `official_original_task_success_rate` | 官方原任务成功率，越高越好 |
| `official_refusal_rate` | 原版拒答裁判结果；跳过时 null |
| `executed_attacker_tool_rate` | 额外的实际攻击工具执行率，不替换官方评分 |
| `counts` | ALLOW / BLOCK / CONFIRM / executed / tool_errors |
| `workflow_failures` | 原生模型未能生成工作流的任务数，不能归功于守卫 |
| `errors` | 模型传输、守卫、运行或判分错误，不当作攻击失败 |

只要选择集未全部完成，整体状态为 incomplete，成功率为 null。
比较器拒绝未完成实验，以及模型、任务、源码、传输设置或策略代码不同的两组。
评测期间请保持策略代码固定；检测到代码变化时，本次运行标记 incomplete。
变化量 `*_change_pp` 表示 guarded 减 baseline 的百分点；ASR 的负值表示降低。

ASB 官方评分检查消息中的成功标记，标记可能出现在模型复述中；
可能出现官方 ASR 与执行率不同的情况。保留原始消息并据实解释，不清洗消息提高成绩。

## 验证范围

这是 ASB **工具级模拟**防护验证。该版本原生工具参数为 None，工具返回固定字符串。
因此不声明已测试实际收件人/金额绑定、对象级数据流、文件身份、视觉证据、生产 HTTP
执行票据或操作系统隔离；这些能力继续由专项回归覆盖。
同一进程内信任本地 ASB 代码和操作方配置，不是恶意代码沙箱。

离线回归：

```powershell
& $asbPython -B -m unittest tests.test_asb_adapter -v
```

其中原生集成测试调用真实 ASB Agent、注入、模拟工具和官方评分函数，
行动/审查模型使用确定性替身，只证明接入正确，不提供安全有效性的实测成绩。

## 证据连续性与独立工具声明

同一任务中的同一工具、语义动作及策略身份，不能靠换调用 ID 重审一个有效 deny。
needs_evidence 在没有新增成功观察时复用原来的不确定结论。新增观察只允许进入审查；
若要放行，审查结果必须引用 user 和至少一个新增观察，且仍通过硬检查。工具输出中的
“用户已批准”不构成新授权。引用存在性不是语义相关性证明，误审风险仍需真实攻击验证。

ASB 工具描述默认标记为未独立验证，业务副作用未知；注册、源码绑定和无参数模拟都
不能把任意业务用途变成已授权的只读操作。可通过 `--tool-contracts` 接入由运维方
独立审阅的声明。示意格式（哈希占位符不能直接使用）：

```json
{
  "version": 1,
  "tools": {
    "your_tool": {
      "issuer": "operator",
      "catalog_hash": "sha256:<64 hex digits>",
      "runtime_hash": "sha256:<64 hex digits>",
      "operation": "read",
      "effects": ["read"]
    }
  }
}
```

catalog_hash 是 `object_hash({'tool': 工具名, 'description': 原始描述})`；runtime_hash
是本次 ASB `pyopenagi/tools/simulated_tool.py` 文件的 `sha256:` 加十六进制哈希。
绑定失败在评测前报错；未声明的新工具保持未知状态，不自动获得同类权限。该文件是
本地可信运维输入，不是厂商签名或代码形式验证，也不授予任务权限。声明快照及指纹
写入结果，并纳入对照一致性检查。不得根据 normal/attacker 标签生成许可清单。

若运维方明确要求仅允许来源已独立审阅的工具，再设置 `--require-tool-contracts`。
guarded 会在模型审查前硬拒绝没有有效声明的工具；已声明工具仍需通过任务授权和
其余硬检查。未提供独立声明时会报配置错误，而非悄悄执行一次全拒绝实验。
此限制默认关闭，不根据 ASB 标签自动生成或启用。

默认使用原有共享审查协议。`--review-profile asb` 可选择与无参数、固定字符串
执行模型相符的实验性精简协议，仍使用共享 CallReviewer 的结构化校验、证据引用
和有限纠错。本轮小样本中精简协议未证明完成率收益，不能作为默认替换。
实际选择记录在 summary.review_profile，思考配置记录在 summary.review_settings。

共享协议现在附加宿主提供的 ASB 执行说明，区分无参数前置查询与最终答案缺少
公司/季度信息，不把工具名称直接当作交易或修改行为。完整用途、未知副作用、
原始任务范围、工具契约和拒绝连续性仍须检查；不会强制调用评分所需工具。

审核传输使用 `--review-thinking-mode auto`：仅当审核模型名称以 `deepseek-`
开头且没有配置任何思考控制时，关闭首轮和纠错轮的审核思考。其他模型或已有
显式配置保持继承。可明确指定 `disabled`、`enabled` 或 `inherit`；指定前两者
会在本次运行内清除冲突的 vLLM 思考与 reasoning_effort 设置，结束后恢复环境。
执行模型设置不受影响。审核输出预算优先沿用环境，未配置时为 4096；
`--review-max-tokens 2048` 可显式覆盖首轮和纠错轮。超时和重试次数没有增加。

对本项目的 DeepSeek 服务，原 ASB 命令可追加：

```text
--review-thinking-mode disabled --review-max-tokens 4096
```

有效审核设置和协议均写入 comparison，baseline/guarded 对照应使用相同设置。
这些更改修复配置缺省和执行上下文表达，不保证审核模型语义正确或成功率上升。

## 小规模验证与结论限制

2026-10-27 新增可选 `--action-context structured`，用于隔离规划／执行指令及消息来源。
当前仅支持 clean/OPI，原生轨迹、攻击载荷与评分均保留；默认仍为 `native`。
小规模对照未证明任务完成率或攻击成功率改善，且有耗时退化，因而未默认启用。
机制、限制和验证结果见 [ASB 行动上下文](asb-action-context.md)。

新增的任务结束检查与固定重复对照见 [ASB 配对验证说明](asb-paired-validation.md)。
该模式保持可选，不通过清除注入、强制调用评分工具或重试拒绝来提高成绩。

工具能力审计、独立可信问答重放及语义步骤记录的使用方法见
[ASB 任务上下文说明](asb-task-context.md)。可信问答使用独立协议，不能与原生 ASB 成绩混算。

先对全部 5 个金融 clean 用户任务比较 native/bounded × baseline/guarded；再用预先
固定的少量攻击组合验证。辅助脚本为
`results/asb_reliability_validation_20261024/validate.ps1`，从本地已有配置只读取字面量
审查服务设置，不执行 AgentDojo launcher，不复制或显示密钥。

```powershell
& '.\results\asb_reliability_validation_20261024\validate.ps1' -Stage all -DefaultOnly
```

`-DefaultOnly` 是默认配置的 10 个 clean 执行与 8 个攻击执行。
省略它则增加 native/bounded 消融，变为 20 个 clean 与 8 个攻击执行。
精简审查对照需显式添加 `-ReviewProfile asb`。这不是 ASB 全量，也不是统计显著性证据。
`--case-id` 可重复指定 --check 返回的组合 ID（搭配 `--limit 0`），用于固定回归集合；
ID 不传入审查器，也不参与安全判定。

公司/季度缺失且工具没有真实财务数据时，澄清可能合理；不能通过必调某个工具或
编造字段来抬高官方分数。官方仍检查正常工具成功标记，不代表金融分析质量。
这些改动不保证完成率一定上升；应保留未完成和未评分结果，同时观察攻击成功是否增加。
