# R-Judge 评测说明

## 主版本：review 直接决策（8098代理当前默认）

```powershell
# 窗口1，项目根目录。审查服务密钥只从环境变量读取。
$env:ICB_INTENT_LLM_BASE_URL = 'https://api.deepseek.com'
$env:ICB_INTENT_LLM_MODEL = 'deepseek-flash'
$env:ICB_INTENT_LLM_API_KEY = '填写审查服务密钥'
python -X utf8 -B -m demo.attacks.rjudge_guard_proxy --protocol review --check-config
python -X utf8 -B -m demo.attacks.rjudge_guard_proxy --protocol review

# 窗口2，R-Judge目录。新别名避免读取旧版rules/effects辅助模式的缓存。
python -X utf8 -B .\eval\safety_judgment.py `
    --model_name 'deepseek-flash-icbguard-review-v2' `
    --model_base 'http://127.0.0.1:8098/v1' --api_key 'local'
```

默认流程复用 `policy.call_review.CallReviewer` 和 `check_hard_boundaries`。
按记录中的用户消息更新可信请求，仅把时间上已出现、且能绑定至单次已允许动作的
环境反馈作为不可信观察。没有 rules/effects 生成，也没有最终记录判别模型。
官方分析请求执行逐次授权并返回固定结构说明，标签请求复用缓存，返回 safe/unsafe。

预先固定的记录级投影规则：硬拒绝或语义deny => unsafe；所有已解析动作通过 => safe；
CONFIRM/needs_evidence、未知工具、无法解析动作、无法绑定的观察、无动作、审查错误 =>
abstain。最后一类返回 undetermined，官方脚本将其计作无效预测并惩罚，绝不补成safe。
该投影是动作授权诊断，不能把干预本身解释成原始整段记录的风险真值。需报告覆盖率。

R-Judge自由文本动作使用本地静态工具注册表和原始参数，不虚构字段角色或来源证明。
它没有AgentDojo原生Schema、实时账户状态、资源证书及执行前版本复核能力，因此属于
review内核的离线适配，并非AgentDojo完整宿主的逐项等价实现。不执行记录中的动作。
工具反馈绑定不明确时停止并弃权，不猜测其归属。保守污染记录不证明真实读取成功。

启动输出 trace_dir，默认位于 results/rjudge_review_<时间戳>。每条公开轨迹按哈希保存
prediction、reason、actions、reviews、elapsed_seconds、review_seconds和review_requests。
文件不写入人工label/risk_description。目录可能包含审查输入诊断，应视作评测数据保存。
elapsed_seconds为首次直接决策全链路耗时，含解析/硬检查/模型请求和恢复，不含官方客户端
缓存读取、进程外限速、官方输出写盘及第二阶段HTTP往返。模型原始审查错误单独保留。
同进程缓存复用第二阶段，正式测量使用新别名和新代理进程，区分两层缓存命中。

旧版策略辅助判别仍可显式使用 `--protocol policy-assisted`，需要配置
RJUDGE_PROXY_UPSTREAM_* 以及 ICB_INTENT_LLM_*。以下旧章节描述该辅助模式。

入口仍是 `demo/attacks/replay_rjudge_symbolic.py`。脚本读取本地数据文件，
不会运行数据集中的命令、发送邮件或执行其他动作。

## 三种模式

| 模式 | 输入与被测对象 | 可解释的结果 |
| --- | --- | --- |
| `official`（默认） | 完整交互记录，基础判别模型 | 官方安全判别流程下的模型成绩 |
| `policy-assisted` | 同一完整记录，加本项目策略引擎的观察结果 | 策略辅助方法成绩；属于扩展协议 |
| `replay` | 原有动作解析与授权重放 | 诊断用途，不是官方判别成绩 |

官方模式不会调用本项目策略引擎。因此评估安全框架贡献时，应固定判别模型，
分别运行 `official` 与 `policy-assisted` 比较，不能将基础模型成绩说成框架成绩。
本脚本只实现 safety judgment，不实现官方另一个 risk identification 的成对评分任务。

## 数据在哪里引入

1. 入口的 `RJUDGE_DATA` 默认指向项目根目录下 `R-Judge/data`。
   可通过 `RJUDGE_DATA` 环境变量或 `--data` 覆盖。
2. `main()` 调用 `load_records(Path(args.data))`，递归读取 JSON，校验字段和重复 ID，
   保留来源文件与 SHA-256。它没有通过 `import R-Judge` 引入 Python 包。
3. `rjudge_judgment.py` 的 `build_messages()` 按官方脚本构造消息：profile、
   所有用户消息、agent thought/action、environment 反馈，保持顺序。
   不把 label、risk_description、goal 元数据加入判别输入。
4. `run_judgment()` 先请求风险分析，再请求 safe/unsafe 标签。
5. `score()` 在预测完成后读取人工 label，计算记录级指标。

对齐依据是 `R-Judge/eval/safety_judgment.py`：
https://github.com/Lordog/R-Judge/blob/main/eval/safety_judgment.py
测试会从本地官方文件提取消息构造代码，比较构造结果和提示词。

## 运行方法（项目根目录，PowerShell）

先检查数据，不调用模型：

```powershell
.venv/Scripts/python.exe -B demo/attacks/replay_rjudge_symbolic.py --validate-only
```

默认要求完整数据集为 569 条，检查发生在 `--limit` 或攻击类型筛选之前。
当前本地发现 564 条，会明确报错。应先恢复完整数据；若仅调试现有子集，
可显式加 `--expected-count 564`，结果会标注数据数量与官方规模不一致。
数量相同也不证明数据版本相同，比较结果时仍需核对导出的文件哈希。

配置支持 `/chat/completions` 的判别服务：

```powershell
$env:RJUDGE_MODEL = "你的模型名称"
$env:RJUDGE_BASE_URL = "https://你的服务地址/v1"
$env:RJUDGE_API_KEY = "你的密钥"
.venv/Scripts/python.exe -B demo/attacks/replay_rjudge_symbolic.py --protocol official
```

也可以使用 `--model` 和 `--base-url`。本地无鉴权服务可以不设置密钥。
协议沿用官方 temperature=0、分析最多500 token，以及 gpt 开头模型标签最多1 token、
其他模型500 token。服务必须支持这些参数；不兼容会标记为请求错误，不会暗中更改参数。

评估策略辅助方法，另配置本项目的意图模型：

```powershell
$env:ICB_INTENT_LLM_MODEL = "你的意图模型名称"
$env:ICB_INTENT_LLM_BASE_URL = "https://你的服务地址/v1"
$env:ICB_INTENT_LLM_API_KEY = "你的密钥"
.venv/Scripts/python.exe -B demo/attacks/replay_rjudge_symbolic.py --protocol policy-assisted
```

两个模型可以相同，也可以不同，应在实验报告中说明。
`--no-rules` 仅关闭辅助规则生成与对应规则检查；`--no-effects` 仅关闭辅助效应画像。
仅关闭其中一项仍需意图模型。两项都关闭是明确的消融设置，不是完整框架成绩。

辅助策略按时间顺序读取动作，只使用当时已出现的 profile/用户消息锚定意图，
不会将环境返回提升为可信用户指令，也不会预读未来工具来生成规则。
遇到第一次 BLOCK/CONFIRM、未支持动作或工具即停止辅助重放。
ALLOW 的数据源读取只做保守 taint 模拟，不表示动作实际执行成功。
辅助证据不足时，判别模型仍可查看完整原始记录；它不能把策略拒绝本身当作风险真值。

## 保持官方 eval 不变的策略评测

`R-Judge/eval/safety_judgment.py` 没有策略插槽。若要保持官方脚本不变，
先在项目环境中启动 OpenAI-compatible 防御代理；官方脚本只负责构造原始
R-Judge 消息和计分。代理仅从这些消息恢复 `profile` 与公开交互轨迹，运行
ICB-Guard，再把策略观察加入官方 reasoning prompt 之前。代理看不到数据文件
中的 `label`、`goal` 或 `risk_description`。

在项目根目录的一个 PowerShell 窗口配置底层判别模型和意图模型。密钥使用
环境变量，不要写入脚本：

```powershell
$env:RJUDGE_PROXY_UPSTREAM_BASE_URL = 'https://provider.example/v1'
$env:RJUDGE_PROXY_UPSTREAM_MODEL = 'your-underlying-model'
$env:RJUDGE_PROXY_UPSTREAM_API_KEY = 'your-provider-key'

$env:ICB_INTENT_LLM_BASE_URL = $env:RJUDGE_PROXY_UPSTREAM_BASE_URL
$env:ICB_INTENT_LLM_MODEL = $env:RJUDGE_PROXY_UPSTREAM_MODEL
$env:ICB_INTENT_LLM_API_KEY = $env:RJUDGE_PROXY_UPSTREAM_API_KEY

& '.\.venv\Scripts\python.exe' -B -m demo.attacks.rjudge_guard_proxy --check-config
& '.\.venv\Scripts\python.exe' -B -m demo.attacks.rjudge_guard_proxy
```

默认监听 `http://127.0.0.1:8098/v1`。如需独立管理员策略，加
`--business-policy <json>`。服务仅接受 R-Judge 官方两阶段消息；普通聊天请求
和流式请求会被拒绝。第二阶段会复用第一阶段的策略证据。

在另一个 PowerShell 窗口进入官方仓库，先运行 raw baseline：

```powershell
Set-Location 'F:/Code/MLLM Agent/R-Judge'
python ./eval/safety_judgment.py `
  --model_name 'your-underlying-model' `
  --model_base 'https://provider.example/v1' `
  --api_key $env:RJUDGE_PROXY_UPSTREAM_API_KEY
```

再通过防御代理运行 guarded。模型名必须使用不同的稳定别名，因为官方缓存键
不包含 `model_base`，复用 baseline 名称会错误命中旧缓存：

```powershell
python ./eval/safety_judgment.py `
  --model_name 'your-underlying-model-icbguard-v1' `
  --model_base 'http://127.0.0.1:8098/v1' `
  --api_key 'local'
```

代理会把别名替换为 `RJUDGE_PROXY_UPSTREAM_MODEL` 后再调用底层服务。比较两次
`statistics.md` 中的 F1、Recall、Specificity 与 Validity。该实验可表述为
“official evaluator, ICBGuard-augmented model”，仍然测量风险识别能力，不是
端到端攻击成功率或任务完成率。正式比较前必须恢复并固定准确的 569 条数据；
当前 564 条只能作为本地子集结果。

常用参数：

```powershell
# 完整数据检查后，只调试前3条
.venv/Scripts/python.exe -B demo/attacks/replay_rjudge_symbolic.py --limit 3
# 指定数据目录
.venv/Scripts/python.exe -B demo/attacks/replay_rjudge_symbolic.py --data 'D:/datasets/R-Judge/data'
# 只评测注入组
.venv/Scripts/python.exe -B demo/attacks/replay_rjudge_symbolic.py --attack-type injection
```

## 指标和输出

unsafe=1，safe=0；报告 F1、Precision、Recall、Specificity、Validity、混淆矩阵，
按攻击类型、应用类别及二者交叉分组统计。无效标签按官方规则在评分端算作错误，
原始预测保留 -1。服务/网络错误也保留并惩罚，但与无效文本分开统计，
整次运行标为 incomplete，退出码2；这类结果不能作为完整 benchmark 成绩。
空分组的指标是 null，非空组的零分母按官方 zero_division=0 处理。

结果默认写入带时间戳的 `results/rjudge_<protocol>_*.json`，包括数据清单、
模型配置、实现哈希、原始分析/输出、逐条错误状态和指标。
同名 `.json.jsonl` 文件逐条刷新，保留已完成进度；当前不支持自动续跑。
`--export` 可指定路径，已有文件不会覆盖。输出含原始数据对话，不包含 API 密钥。

原有 `--protocol replay` 仅保留作兼容诊断：它仍不具备完整对话理解；
网关路径只授权、不消费执行票据，不能和离线 taint 模拟当成同等实验。
其输出只报告条件干预率等描述指标，不报告官方 F1 或真实攻击成功率。

## 验证

```powershell
.venv/Scripts/python.exe -B -m unittest tests.test_rjudge_evaluation tests.test_security_hardening
```

测试使用假模型响应，不消耗模型额度，不执行数据集动作。
