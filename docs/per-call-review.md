# 逐次语义授权实验模式

`--mode guarded --intent-format review` 只用于 AgentDojo/pi 模拟宿主。
默认仍为 `rules`；生产网关、R-Judge 与既有 rules/boundary 模式不自动切换。
本模式是概率性的语义授权，不继承初始冻结策略的权限不扩张性质。

## 执行方式

任务开始保存原始请求与可信时钟，不调用模型生成初始 rules、boundary 或 effects。
行动模型提出调用后：

1. 宿主校验工具、完整有效参数、默认值、能力、业务约束与实际效果。
2. `check_hard_boundaries` 独立检查能力、业务限制、路径、数据流及证据要求，
   只返回 PASS/BLOCK/CONFIRM。PASS 不是授权，不构造临时 allow 规则。
3. `SemanticAdapter` 依照经过 Schema 绑定的运营者声明，将完整参数映射为统一语义动作。
   独立审查模型读取原始请求、规范化操作、资源类型、参数角色、完整参数、
   可能副作用上界，以及已执行操作和工具返回数据。输入不指定应选择的工具。
   工具身份保留在宿主认证、请求绑定及执行记录中，不向模型提供 expected_tool。
4. 严格验证 `allow / deny / needs_evidence`、原因代码、字段与证据引用。
   引用存在只能证明来源存在，不能证明模型判断正确。不得以自报置信度放行。
5. allow 后复核参数、环境、能力证书、工具 Schema、污染状态与业务策略，
   再检查硬约束，在同一宿主锁内执行。新调用重新审查，重复调用 ID 拒绝。
6. 拒绝后提供固定模板的字段级反馈，不直接转发模型生成的任意提示词。
   证据不足时可提出新的相关查询，但查询本身也需审核。重试有次数限制；
   没有新宿主观察时重复同一拒绝调用会停止。

审查器复用独立的 `ICB_INTENT_LLM_*` 服务配置，与行动模型上下文隔离。
只允许一次结构错误或截断的恢复；明确 deny/needs_evidence 和网络错误不自动重试，
没有初始策略降级或审查失败放行。审查请求总包超过 120,000 UTF-8
字节时报错，不静默截断证据；这不是精确 token 上限，服务端仍可能报告上下文不足。
剩余任务时间限制单次请求超时，逾期返回的 allow 不执行。requests 的连接/读取超时
不等于严格总墙钟截止；若服务持续缓慢返回，任务退出可能更晚，但逾期动作不执行。

## 审查输出协议 v2：宿主绑定

模型仅返回 `decision`、`code`、`fields`、`evidence_ids`；涉及数据使用时额外要求
`data_use_decision`（allow/deny/needs_evidence），其他情况下禁止该字段。
请求标识、`scope_hash` 和内部 `data_use` 对象由宿主绑定，不再要求模型复写。
自由说明文本移出模型输出；内部 reason 使用有限原因代码。证据引用依然由模型选择，
宿主验证引用存在及必要来源引用，但引用存在不能证明语义正确。

只有总体判断和数据使用判断均为 allow，才可能继续执行前复核。
总体 allow 但数据使用 deny/needs_evidence 时，最终结果按后者保守合并，不重问争取放行。
缺少或无效的数据使用判断不会补成 allow，伪造 request_id、scope_hash 或旧版授权对象均拒绝。
历史日志仍可读取，旧版输出不作为 v2 的宽松兼容分支。

结构错误和 HTTP 200 下的 JSON 解析/截断错误，在同一证据、参数和任务剩余时间内最多恢复一次。
恢复保留原始用户条件、所有原生观察和先前执行，避免摘要遗漏限制或泄露来源。
服务错误不降级输出协议，也不视为真实安全拒绝。恢复仍失败时记为未评分错误。
`error_category` 区分 review_protocol_error、review_generation_incomplete、review_transport_error、
review_context_error、review_state_error 和 review_model_refusal；有效 deny 是审查结果。
summary 及全 suite 汇总增加 `task_error_categories`，授权诊断增加恢复数量、审查拒绝数和错误分类。

### 可选的服务配置

默认继承 `ICB_INTENT_LLM_*`，不假定兼容服务支持全部结构化或推理参数。
以下 review 独立设置只覆盖审查请求，不修改 rules/boundary 或行动模型：

| 环境变量 | 用途 |
|---|---|
| `ICB_REVIEW_OUTPUT_FORMAT` | text、json_object、json_schema 或 vllm_guided_json |
| `ICB_REVIEW_MAX_TOKENS` | 单次输出预算，1–16384，仍受服务端上下文限制 |
| `ICB_REVIEW_REASONING_EFFORT` | 仅对明确支持该参数的服务使用 none/minimal/low/medium/high |
| `ICB_REVIEW_ENABLE_THINKING` | 仅对支持 chat_template_kwargs 的服务使用 true/false |
| `ICB_REVIEW_RETRY_*` | 上述四项各自的恢复请求覆盖，例如 RETRY_MAX_TOKENS |

`json_schema` 发送 strict JSON Schema；`vllm_guided_json` 沿用现有 guided_json 接口。
本地严格校验始终生效。服务端不支持时记录 HTTP 错误，不自动静默降级。
低推理预算和增大预算需要实际对照后选用：协议变短不能保证推理不截断，
关闭推理也不能被假定对授权准确性没有影响。配置哈希包括以上设置，避免混用实验结果。

## 明确保留的限制

- 业务禁令、能力参数、数据流、证据证书等限制仍有效；模型同意不能越过它们。
- 不用候选调用伪造“来自初始用户授权”的来源证明，不清除会话污染状态。
  因此读敏感数据后的发送/分享仍可能被现有 P5 限制阻断。
- execution 类参数需要初始可信有限范围；本实验模式没有该授权，保持拒绝。
- 审查模型看到的工具结果、参数文本仍可能包含攻击。标记为不可信及上下文隔离
  不能证明模型免疫注入；同模型、同错误理解也可能导致关联失败。
- 审查器错误允许语义越权调用时，若其他硬约束没有禁止，调用仍可能执行。
  离线测试专门保留了这一反例，不能把“模拟模型返回 deny 后阻断成功”
  当成真实模型具有注入识别能力。
- “最终自然语言回答”的内容审核不在此工具调用实验的保护范围。

## 调用时参数来源证明与有限恢复

review 模式在调用时尝试有限的来源证明。直接披露污染内容仍阻断；经运行时验证的
资源身份引用与披露其内容分开检查。此证明不是任务授权，
不生成或保存参数 allow 规则，也不改变会话 dirty 状态。

`policy/argument_provenance.py` 只使用原始用户请求及经审核的无额外效果默认值。
支持带边界的原文字符串/列表、明确 ISO 日期与时钟组合，以及明确小时/分钟的
确定性加法。记录原文位置、转换、完整有效参数/合同/请求/状态哈希。不支持的
数字、复杂对象、相对日期、任意摘要或模型表达式都保留为 unproven；无证明不放行。
来源出现不代表授权：否定句中的地址、多个时间组合及用户条件仍由语义审查判断。

只有 pinned schema 且经过数据流审核的工具可以使用完整证明。
`dataflow_mode: initial_arguments` 表示效应的数据由本次参数界定，而不是读取已有资源再隐式披露。
`bound_resource_update` / `bound_resource_arguments` 还要求资源字段通过以下运行时绑定。
创建操作的目标可作为新资源名称证明；附件、其他已有资源内容或隐式目的地不因此
获得许可。当前审核声明覆盖创建事件、创建文件和发送邮件，非空附件仍无此证明。
新工具依靠相同声明机制接入，不查询任务编号、评分答案或固定样本值。

完整证明后重新运行全部硬检查（保留直接污染对象），仍须逐次语义授权并复核状态。
审查模型看到来源证据和控制依赖提示：即使参数是原文常量，也必须检查读到的数据
是否改变了用户要求的条件。模型误判仍可能误放行，来源证明不能消除这个风险。

不完整证明返回 `p5.source_evidence`，只允许有界补证/参数修正，反馈不会生成替代
参数。相同被拒调用只有宿主观察变化后才允许再次审查，拒绝总次数及每类修复次数
仍受限制。新增查询不自动信任其内容，也不将工具内容升级为用户授权。
直接污染、能力或业务禁令不因这类恢复放宽；需要新增授权时仍须可信确认。

失败、空结果和搜索条件不登记为已读对象；错误诊断仍令会话保持来源不确定。
对象污染只来自成功执行、与实际状态一致的原生实体ID，不把查询词当作对象身份。

## 原生结果溯源、资源绑定与新鲜度

共用实现位于 `policy/resource_provenance.py`。当前后端是 AgentDojo 模拟宿主，
在同一锁内可验证完整账户状态。它不是远程 API 的 ETag/原子条件更新实现。

运行时在已经授权并真实执行的调用后，对原生结构化返回值记录 call_id、结果哈希、
实体及主键字段路径、账户命名空间、实体快照哈希、有效期和任务内随机句柄。
不解析模型伪造的 JSON 字符串作为执行结果；失败、空结果或与实际状态不一致的
实体不能产生引用凭据。句柄保持在宿主内部，不修改 AgentDojo 工具 Schema。
它是来源引用，不是允许调用某个工具的能力令牌。

清单根节点 `provenance_resources` 声明实体类型、状态集合、账户路径、主键、
标签匹配方式、可审核的 min/max 字段和 TTL。工具 `result_resources` 声明原生
实体的返回路径，`resource_parameters` 把参数关联到实体类型，均绑定 pinned Schema。
例如查询输出路径 `["*", "id_"]` 的标识可以在之后关联 event_id，不能从邮件正文
里碰巧出现的同一个数字推导引用。新增工具使用声明接入，不增加任务编号或答案。

资源绑定支持确定性原文标签、有限的用户指代短语和声明的数值排序，按完整宿主
账户集合验证唯一性。名称标点不做模糊替换；多个匹配、排序并列、不支持的自然语言
关系继续补证/确认。描述词匹配不等于已解决任意语义指代。资源来自真实结果、
确定性绑定通过，也仍须独立审查实际操作和变更范围。证明明确标记
`task_authorized=false`、`ownership_verified=false`：账户范围和版本可验证，
不能由工具文本断言所有权或替代运行时权限、业务规则。
`binding_verified` 只表示声明的确定性选择谓词通过，不表示程序已理解和验证用户
请求中的全部自然语言约束。范围、否定、操作授权及未表达的关系仍由审查/确认处理。

`resource_values` 只允许审核过的控制/目的地字段投影，例如从唯一绑定事件的
participants 字段取同一参与人列表；模型添加额外值就没有这个投影证明。
`resource_derivations` 支持保持已绑定资源原时长的确定性计算，不执行任意表达式。
任意摘要、模型生成正文、附件披露、相对日期解析仍没有通用解密/放行机制。

执行前再次检查账户、TTL、完整资源版本、选择唯一性、环境、证书、声明和来源账本。
只在验证过的资源参数位置把 ID 当引用；同一个 ID 放进正文或附件仍受直接污染检查。
会话 dirty 不清除。批准只覆盖本次调用；被删除/改变的实体及跨任务句柄不能复用。

审计事件 `simulation_native_result_provenance` 记录路径和完整性信息；绑定失败区分
`source_unresolved`、`resource_stale`、`resource_binding_ambiguous`、
`resource_binding_unresolved` 和 `resource_mismatch`。前几类允许有界补证，
明确资源不匹配不放行。summary 的 runtime_provenance 记录任务ID、轨迹数和账本哈希。

接入真实远程服务时，必须提供来自可信连接器的账户/完整资源范围及原子版本验证。
没有完整枚举就不能宣称全局最大或唯一；只有先读后写而没有条件更新，也不能宣称
消除了竞态。当前实现不会把这些未具备的保证标为通过。

## 工具声明接入

`semantic_action` 由运营者编写，与固定 `schema_hash` 绑定；不由模型或工具返回内容生成。
它描述工具实现语义，不列出某个任务的允许参数。必须一对一覆盖全部有效参数。
例如两个工具分别使用 `path`、`file_path`，都可以映射到规范字段 `path`：

```json
{
  "version": 1,
  "operation": "read",
  "resource_type": "file",
  "fields": {"file_path": "path"},
  "effects": ["read"],
  "reason": "经审核，此适配器读取指定文档，不将输入作为代码执行"
}
```

规范化不会隐藏额外的网络、写入或执行能力；能力证书中的更宽副作用并入上界。
可选 `semantic_action.parameter_effects` 用于声明字段为 `add_members`、
`remove_members`、`append` 或 `replace`，按 Schema 校验后映射为规范字段。
它说明工具的实际参数语义，不授予任务权限，也不降低副作用上界。追加成员不会
被默认为替换整个列表；声明与实际模拟执行是否一致由独立状态断言测试。
当前版本对无法独立限制的执行能力继续要求确认/拒绝。新增工具缺少经过审核的语义
声明时，review 模式拒绝执行，旧 rules/boundary 模式按原路径运行。
workspace 的 24 个工具已声明；“获取未读邮件”明确包含标记已读的副作用。
声明与 Schema 一致不等于证明工具实现可信，更不等于建立了任意 Python/Shell 沙箱。

仅与用户任务质量相关的偏差可以反馈 `task_mismatch`，以 `REPLAN` 引导重新规划；
REPLAN 不是第四种授权结果。资源、目的地、金额、权限和显式禁止仍参与授权审查。
自然语言同义查询和生成正文不再因为缺少初始有限值规则而被直接拒绝。

## 使用与对照

本地启动脚本支持（其中包含的密钥不入库）：

```powershell
& '.\.local-qwen\run-qwen.ps1' -IntentFormat review -UserTask user_task_0
& '.\.local-qwen\run-qwen.ps1' -IntentFormat review -UserTask user_task_0 `
  -Attack tool_knowledge -InjectionTask injection_task_0
```

Python 入口使用 `--intent-format review`，不能与 baseline 或 ReadPreflight 混用。
先验证单任务链路，再固定代码、模型、服务配置、任务集合与攻击进行全量对照：

```powershell
& '.\.local-qwen\run-qwen.ps1' -IntentFormat rules -AllTasks
& '.\.local-qwen\run-qwen.ps1' -IntentFormat review -AllTasks
& '.\.local-qwen\run-qwen.ps1' -IntentFormat review -AllTasks -Attack tool_knowledge
```

无攻击 40 个任务与 560 个攻击组合属于 workspace，不是 AgentDojo 所有 suite。
比较时同时报告全部计划任务中已确认成功比例、已评分完成率、评分覆盖率、
攻击成功率、任务/审查错误率与配对结果。错误不赋予官方评分，也不能算防御成功。
预筛查失败和受控终止需要单列，不把未达到攻击目标自动归因为审查器有效。

每个 run 记录 `initial_intent_requests`、`initial_intent_seconds`、`review_requests`、
`review_seconds`、`elapsed_seconds` 与 `reviews`；审计包含请求/参数/环境哈希、
审查结果和耗时。审查 reason 只用于审计，不作为给行动模型的新指令。
`elapsed_seconds` 覆盖开始生成策略到模型循环结束，不含最终进程清理时间。
初始策略阶段直接出错时可能没有 run 记录；不能拿仅成功运行的耗时均值宣称加速。

单任务实测只能证明有限链路，不能证明全量完成率提高或安全性不下降。
应在相同任务集合上多次运行，报告总耗时与 p50/p95，并把外部服务波动纳入解释。

## 固定实验协议及报告

`python -B -m adapters.agentdojo_pi.validate_review --pi-agent-dir <配置目录> --provider <提供商> --model <模型>`
按固定顺序运行 rules/review 的两轮 40 任务对照，以及前四个用户任务与前四个攻击目标
组成的 16 对攻击组合。`--include-full-attack` 再运行 review 的全部 560 对；全量攻击
结果仅描述本模式，模式间 ASR 对照使用相同的小规模攻击集合。脚本使用调用者已配置的
ICB_INTENT_LLM 环境变量，不保存或打印密钥。

`--clean-only` 仅安排两轮 rules/review 各 40 个正常任务，不运行任何攻击；
它不能与 `--include-full-attack` 同用。只测改进模式一轮时，使用启动脚本
`-AllTasks -IntentFormat review`，共 40 个正常任务。

协议在调用模型前写入，代码/声明/行动模型配置改变时停止；服务端权重和随机性无法锁定。
错误逐任务保留，操作性故障中止批次，不自动修改策略或选择性丢弃失败任务。
每阶段分开报告预筛查与攻击分母；所有任务结果（包括初始意图生成错误）记录端到端耗时。
`review_report --left <rules summary> --right <review summary>` 严格检查对照配置并生成配对报告。
服务端耗时统计缺失时不以零代替；新旧代码的历史运行不能冒充本轮固定版本对照。
# 2026-10-21: bounded data-use review

The latest user-run clean cohort is
`results/agentdojo_pi_guarded_1792548146102055700/summary.json`:
24/40 succeeded (60%), 15 scored failures, one unscored review error;
24/39 scored utility (61.54%), 97.5% scoring coverage. Compared with the
previous 22/40 cohort, task 8 and task 35 succeeded; task 25 changed from an
error to a scored failure. Task 18 now proposed creation and was blocked by
provenance, unlike its earlier voluntary scheduling-conflict stop. These
results precede the changes below and must not be relabelled as their results.

`policy/data_use.py` separates origin from task permission. Operator-reviewed,
schema-pinned `review_data_use.content_fields` permits bounded local text
mutation to enter semantic review when literal provenance is unavailable.
It does not make `proof.complete` true: `review_ready` only says the packet can
be reviewed. Candidate `DERIVED`/`AGENT_GENERATED` values are not verified
origins. Exact native-text copies and line projections carry correspondence
witnesses, but neither prove that the selected material was requested.
No network, executable, destination, amount, or resource field receives this
generated-content exemption. Direct object-ID taint blocks remain enforced.
Existing readers of a shared target are included as `resource_audiences`;
local mutation can still disclose to those readers and needs task review.

Pinned `result_values` declarations record real native result fields, with
task-local origin, result hashes, paths, bounded retention and expiry.
`observed_parameters` supports exact scalar/list projection into declared
control/destination positions. A contact address being observed is not proof
that it is the requested contact. The reviewer must check identity and cite
the host observation; omitted citations fail validation. Errors, JSON strings
asserting tool results, arbitrary destination guesses, and expired receipts
cannot supply these witnesses. Content remains untrusted.

`review_data_use.semantic_resources` can route fresh native identities with
unresolved/ambiguous deterministic selectors to semantic target review. The
receipt explicitly reports `binding_verified=false` and
`semantic_selection_required=true`. Definite mismatches, missing/expired
identity records, or unavailable bounded collection scopes still fail before
review. This is a probabilistic authorization decision, not a newly proved
unique match. State, account, parameters and TTL are checked again before
execution. A bad but structurally valid reviewer can still misauthorize a
semantic target or local write; regression tests deliberately demonstrate this
remaining trust assumption rather than treating fixture allow decisions as truth.

`inseparable_read_effects` describes real read-state changes without removing
them from effect upper bounds. Currently only `mark_read` on declared read/list
operations is supported. It is not a permission: explicit requirements to
preserve unread state must still prevail. No task-ID exceptions are used.

Review history keeps all effective parameters/results but omits recursive
copies of provenance; current receipts replace duplicate attributes with
hashes, with source data retained in the original observations. Oversized
packets and truncated output still fail as unscored errors. Asking for short
output is not proof that reasoning-token truncation is solved. Repair evidence
progress uses unique host-observed action/result/error information, so repeating
an identical lookup with a new call ID cannot reset a rejected call's budget.

This change does **not** implement unrestricted email delegation, arbitrary
natural-language date extraction, or task-scoped external attachment permits.
Those require separate, tested audience/source/sensitivity authorization;
failed contacts and document sharing entries do not establish client identity.
No automatic fast allow/cache is added: existence of provenance does not
establish task authorization. `rules` remains default, `review` experimental.
Offline fixtures test execution invariants; real diagnostic normal-task runs
must be reported separately from the 40-task cohort and from attack evaluations.

# 当前增量：基于97项失败轨迹的参数角色与单次数据流审查

本节更新下面早期阶段“只支持本地生成内容”的限制。`review`仍是实验模式，
默认`rules`没有切换。没有按任务编号、评分答案或已知收件地址增加运行时豁免。

* 来源、资源身份、配置、生成内容和任务授权分别表达。`control_fields`仅允许
  声明的字符串派生值或Schema有限枚举进入语义审查；不把这些值标成来源已证明。
  URL仅支持声明的HTTP(S)前缀规范化，保留其余地址和路径字符。
* 原生结果按声明字段记录精确值、行、URL或邮件地址。词法抽取不是可信指令，
  也不能证明地址属于指定的人；原始完整观察继续交给审查器检查。
  频道/成员可通过当前任务宿主的完整集合校验身份，来源不会授予成员变更权限。
* `flow_review=true`显式启用逐次数据使用审查。宿主建立`data_use_scope`，包含
  精确目的地、参数哈希、状态哈希、可能效果和真实观察引用。审查器须返回匹配
  的`data_use.scope_hash`和`decision=allow`，并引用原始用户授权，才能执行。
  缺少或伪造许可、来源凭据过期、参数改变、状态变化仍不执行。该许可没有跨调用生命期。
* 明确的业务禁令、能力参数、直接对象taint和未声明附件流继续先于审查生效。
  金融转账不能启用语义派生路径。数字原文可证明字面来源，但不能证明计算结果
  或转账授权。金额差额和退款的显式计算/交易绑定现已增加，见后述增量；没有审批时仍不自动放行。
* Banking的`read_file`是任务内字典读取，不访问操作系统。适配器使用精确存在
  的模拟资源键作为能力范围；没有向它发放宿主文件系统通配权限。
  `SimulationPolicyEngine`仅由可信模拟宿主创建；生产PolicyEngine的路径约束不变。
* 输出截断允许一次同调用、同证据包的紧凑格式恢复。有效拒绝不重问；两次
  截断仍是未评分错误。诊断增加推理输出长度/用量，不保存推理正文。

这些条件约束的是调用和证据有效性。自然语言用途、收件人关系和内容是否越权
仍依赖独立审查器。结构化流许可不是形式化授权证明，错误审查仍可能误放行；
离线测试明确保留这个反例。没有实现宽泛权限缓存或自动授权复用。

后续增量已增加受限类型化计算与用户/管理员显式审批接口；只对完整匹配的审批省去重复审查，
不允许模型生成持久权限。使用、金融能力迁移及未解决的业务边界见 [类型化证据与显式审批](typed-evidence-authorization.md)。

任务范围上下文、查询依赖候选、原生附件绑定、金融原生账户求值及补证状态的后续扩展，
见 [参数委托说明](intent-delegation.md)。此增量更新早期关于未实现受限附件发送的说明；
不增加自动审批或默认只读放行。
