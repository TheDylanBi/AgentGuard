# ICB-Guard

Agent 动作授权网关：管理员能力上限、可信用户意图、符号策略、行为对齐、视觉证据、敏感数据流检查，以及单次审批和执行凭证。

本版本包含不兼容的安全修复。旧协议与历史实验归档在 [历史 README](docs/legacy/README-pre-hardening.md)，其防御率不代表当前版本的端到端执行安全。

## 安全契约

1. 管理员注册工具及能力上限。执行身份不能注册工具或批准自己。
2. 可信用户入口通过 `/anchor_intent` 建立会话策略。客户端画像不能建立或替换服务器策略。
3. `/authorize` 先检查硬约束，再返回 `BLOCK`、`CONFIRM` 或 `ALLOW`。
4. `CONFIRM` 由独立审批身份批准，仅覆盖完整参数相同的单次动作，不产生永久规则。
5. 执行端携带审批 ticket 重新调用 `/authorize`；硬拒绝不能被人工确认覆盖。
6. `ALLOW` 返回短时、一次性的 `execution_ticket`。生产模式调用 `/execute`，由服务端固定实现执行文件操作；不允许客户端消费票据后自行执行。
7. `/execute` 校验完整动作、工具、会话、策略轮次、敏感数据状态、证据及文件资源绑定，再次检查授权，并在持有同一组资源句柄期间执行。过期、重复使用、参数、策略或文件变化都会失败。
8. 非成功 HTTP 响应、未知 verdict、审批失败均不得继续执行。执行前日志失败则不产生文件写入；执行中/完成后失败可能已有部分或完整效果，不能自动重试。审批超限阻止请求，不自动放行。

`decision_id` 是审计标识，不是执行权限。签名证明载荷来源与完整性，不能把页面内容变成用户授权。

## 配置与身份

默认生产模式，安全配置不完整时拒绝启动。

| 配置 | 用途 |
|---|---|
| `ICB_STATE_DIR` | 工作区外的网关专用目录，存储新密钥与审计日志 |
| `ICB_EXECUTOR_TOKEN` | `/authorize`、`/execute` 及登记浏览器的证据读取；开发兼容模式才允许 `/consume` |
| `ICB_ADMIN_TOKEN` | 注册/撤销工具，读取审计证书 |
| `ICB_INTENT_TOKEN` | 建立/替换用户意图，关闭会话 |
| `ICB_APPROVER_TOKEN` | 单次人工审批 |
| `ICB_CDP_ENDPOINTS` | 管理员登记的完整 CDP 地址，逗号分隔；默认无可用地址 |
| `ICB_INTENT_LLM_API_KEY` | 独立意图分析服务；缺失不产生默认放行 |

四个角色凭证必须不同且各至少 32 个字符。网关支持 `ICB_<ROLE>_TOKEN_FILE` 从工作区外文件加载对应凭证。旧 `ICB_GATEWAY_TOKEN` 不再兼容。

管理员在网关服务账户下准备 Agent 无法读写的目录，再生成新密钥：

```powershell
python -m gateway.provision --state-dir C:/ICBGuardState-v2
```

该命令生成新凭证，不覆盖已有文件，不在终端输出秘密。Windows 管理员必须设置目录 ACL；仅有路径隔离或 `chmod` 不代表 Windows 权限隔离。分别向可信组件分发对应身份，执行器不得持有管理员凭证。

设置 `ICB_STATE_DIR` 和四个角色的 token 或 token 文件后启动：

```powershell
python -m gateway.main
```

会话、审批和执行凭证目前存于内存，**只支持一个网关进程/worker**。重启使旧授权失效，需重新注册工具、建立意图。生产网关代码、策略文件、服务环境和状态目录必须由独立账户保护，不能使用 Agent 可写的项目副本运行服务。

开发演示可显式设置 `ICB_DEV_MODE=1`，这不关闭接口认证。只有同时设置 `ICB_LOAD_DOTENV=1` 才读取项目 `.env`。开发模式不能处理真实敏感数据。

生产模式强制受控执行；开发模式可设置 `ICB_CONTROLLED_EXECUTION=1` 测试同一执行路径。首版支持 Windows 本地 NTFS 的 UTF-8 文件读取、覆盖与新建，单文件最多4 MiB；其他动作拒绝执行。配置、API、兼容性和部署前提见 [受控执行与资源绑定](docs/controlled-execution.md)。

## 能力与路径

能力模型保留 `effect_type`、`target_type`、`parameter_constraints`；未知字段报错，旧 `network`/`credential` 标记转换成对应细粒度字段。

文件能力只支持绝对精确路径和尾部 `/*` 的目录授权，空列表表示没有权限。按本机文件系统解析路径后检查根目录关系，拒绝相对路径、目录穿越、外平台路径和不支持的通配模式。受控执行额外绑定文件身份/内容与祖先目录身份，通过 Windows 句柄限制并发替换；符号链接、目录联接、多硬链接及远程路径拒绝执行。

符号授权保留原始参数语义，不将 shell 命令或路径整体转小写、百分号解码后视为同一操作。敏感参数要求每个接受分支都有正向有限约束；`recipient == allowed OR true` 不构成权限边界。

`parameter_constraints` 是管理员声明的硬约束：注册时校验格式，授权和执行票据消费时均检查；违反约束返回 `BLOCK / capability.parameters`，意图规则和人工审批都不能扩大该边界。支持严格类型、有限允许值、数值上下限、字符串/数组长度、数组元素和嵌套字段；被约束字段默认必填，不做字符串转数字等隐式转换。不支持的约束写法会拒绝注册。它不是完整 JSON Schema，也不替代执行器隔离。配置格式见 [参数硬约束说明](docs/parameter-constraints.md)。现有空约束声明保持兼容；业务上限必须由管理员实际配置。

## SDK / pi

独立业务规则可通过管理员文件 `ICB_BUSINESS_POLICY_FILE` 配置。默认空规则，不额外添加禁令。
支持按动作硬拒绝、或强制参数边界；用户意图和人工确认不能覆盖。配置启动时加载，
错误文件拒绝启动，修改需重启。详见 [独立业务安全规则](docs/business-policy.md)。

管理客户端使用管理员身份注册工具；执行客户端只接收证书 ID：

```python
executor = ICBGuardClient(token=executor_token)
executor.use_capability("my_tool", provisioned_certificate_id)
intent_client.anchor_intent(user_prompt, session_id=executor.session_id)
```

`guard` 与 LangChain 包装器提交实际函数绑定的完整 JSON 参数。在受控模式调用 `/execute` 并返回输出字典，不调用传入的本地函数；仅开发兼容模式保留消费凭证后调用函数。自定义类型需要专用适配器，不能用 `str()` 替代参数。BrowserGym 不再把未知动作映射成 click，且不在受控模式执行本地回调。

pi 需要 `ICB_CAPABILITY_CERT_ID`（管理员以 `tool_id=pi_agent` 注册），以及执行、可信意图和可信 UI 审批通道的独立身份。自动注册与关闭拦截的环境开关已移除；缺失意图、网关异常、未接入授权的工具均停止执行。可信适配器及凭证不得暴露给模型或子进程。

当前 pi 内置工具拦截器不能替换实际执行，因此受控模式明确阻断该路径，不会先远程执行又重复执行本地工具；需用 `/execute` 接入固定文件原语。旧演示协议仅适用于开发兼容模式。

`gui_click`、`browser_click`、`browser_type` 是**授权预览工具**，不会真正点击或输入，不能作为真实浏览器端到端执行已经通过的依据。

## 执行边界与剩余限制

- **生产模式禁用宿主机 shell 及声明为任意进程执行的工具**。声明 `network=denied` 不能阻止普通 shell 联网。恢复该功能前必须接入由操作系统/容器强制约束的独立执行器，不能用开发模式替代沙箱。
- 网关不是任意代码沙箱。受控执行器只提供固定文件原语，不运行客户端工具实现。部署时仍需用独立账户和 ACL 让服务成为访问受保护资源的唯一主体；本轮没有自动设置主机账户/ACL，不能把同账户运行视为权限隔离。
- attached 模式仅采用登记浏览器的实时采集结果。客户端截图/a11y 最多提供低可信证据；元素真实存在不等于动作安全。
- 敏感来源在执行凭证消费时保守标记，即使实际读取失败也可能保持 taint。taint 递归检查参数字典值和数组元素，直接对象引用硬拒绝；扫描超过64层/10,000节点或遇到非 JSON、循环结构时，对已污染会话的 sink 硬拒绝。字段名和字符串内嵌 JSON 不作为结构化引用解析，派生内容仍需确认。这仍是对象/会话级近似，不是完整数据流系统。
- 审计条目具备哈希链与签名，默认不保存原始截图和完整动作正文。整条日志截断仍需外部可信检查点或 WORM 存储检测；本地日志不能声称不可删除。
- 旧仓库密钥和 `.env` 不再默认加载。停止 Git 跟踪不清理历史；若曾推送真实凭证，需轮换相关服务秘密，并另行按仓库维护流程清理历史。不要复制旧仓库密钥到新目录继续使用。
- 这是单个可信部署域的服务身份模型，不是多租户身份系统。多用户部署还需用户/租户与会话、工具之间的权限绑定。

## 验证

新回归使用临时密钥、日志和模拟模型/浏览器，不接触实际敏感数据或在线模型：

```powershell
python -B -m unittest discover -s tests -p test_security_hardening.py -v
python -B -m unittest tests.test_controlled_execution -v
node tests/test_pi_adapter.mjs
python -B tests/test_symbolic.py
python -B tests/test_taint.py
python -B tests/test_certificate.py
python -B tests/test_behavior_alignment.py
python -B tests/test_slipped_regression.py
python -B tests/test_feedback_loop.py --gateway
```

Node 测试需要 Node 22.13+，模拟 pi 接口，不启动实际 pi 或浏览器。

R-Judge 在线评估分别使用管理员注册、可信意图入口和执行身份，不再读取网关私钥伪造画像。报告分别标明 `ALLOW/BLOCK/CONFIRM`、正常样本干预率及错误记录数；没有真实执行和逐动作危害标签时，`attack_success_rate` 为 `null`。历史结果保留原样，不能用于宣称本次修复后的防御效果。
