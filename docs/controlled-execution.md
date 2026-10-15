# 受控执行与文件资源绑定

生产模式的执行链为：`/authorize → 必要时审批及重新授权 → /execute`。
`/execute` 由网关执行固定文件原语，不加载客户端代码，不运行 shell 或任意函数。
`/consume` 在生产模式拒绝请求。只返回 `ALLOW` 并不表示操作已经执行。

## 支持范围与模式

| 项目 | 首版行为 |
|---|---|
| 平台 | Windows，固定本地 NTFS 卷；其他平台或卷拒绝执行 |
| `read_file` | 读取已有 UTF-8 文件，返回 `{"content": "…", "encoding": "utf-8"}` |
| `write_file` | 将 `payload.content` 作为 UTF-8 文本覆盖或新建文件，返回 `{"bytes_written": N}` |
| 资源限制 | 现有文件和待写内容各最多4 MiB，路径最长240字符 |
| 路径 | 绝对本地路径；必须满足能力证书和全部原有策略 |
| 参数 | `read_file` 无额外参数；`write_file` 必须有字符串 `content`；可带与目标严格一致的 `path`/`target` 别名 |
| 拒绝项 | 未知参数、offset/limit、追加/局部编辑、任意编码、目录创建、远程路径、ADS、设备路径、符号链接/目录联接、多硬链接 |
| 其他动作 | 浏览器、上传、邮件、shell、自定义动作没有受控执行器，返回 `executor.unsupported` |

生产模式始终启用，不提供降级开关。开发模式 `ICB_DEV_MODE=1` 默认保留原有可信客户端演示协议；同时设置 `ICB_CONTROLLED_EXECUTION=1` 可测试受控路径。`/health` 和授权响应返回 `execution_mode`。两种模式的票据不能互用。

默认不增加业务禁令。此处的拒绝项属于执行器尚不能安全实现的技术边界，不替代管理员业务规则。

## 绑定如何工作

1. 策略得出 ALLOW/CONFIRM 后，服务从卷根开始打开并保持祖先目录句柄，拒绝重解析点。打开文件时不允许其他写入/删除共享，不在授权阶段截断或新建文件。
2. 保存祖先目录身份、文件卷号/文件 ID/创建时间/最后写入时间/大小及 SHA-256。授权快照完成后关闭句柄，不会在等待人工审批期间长时间锁文件。
3. 需要审批时，审批票据同时绑定该资源快照。批准后重新授权，如果资源不同则阻断；不能把对旧文件的批准转用于新文件。
4. `/execute` 先取走一次性票据，验证动作、会话、轮次和状态，再重新取得资源句柄。快照不一致则拒绝，并要求重新授权。
5. 在句柄仍保持打开期间重新检查能力、业务规则、意图、taint 和证据，记录执行开始，再通过同一个文件句柄写入；读取返回从该句柄取得的快照内容。不会重新按路径调用客户端函数。
6. 新文件绑定父目录身份和“目标不存在”状态，在最终执行时使用 `CREATE_NEW` 独占创建。若有其他进程抢先创建，操作失败，不覆盖对方文件。

文件修改时间被恢复也不能绕过内容摘要校验；内容相同但文件身份不同也会被拒绝。普通并发文件写入、删除及祖先目录改名在持有句柄期间被 Windows 共享规则拒绝。若资源被其他程序占用而无法取得所需句柄，执行器拒绝，不回退到普通 `open()`。

**实测边界：共享锁不能阻止具备相应权限的进程进行元数据层面的硬链接创建。** 执行前（及写入后）会复查链接数，发现异常即失败，但复查不能消除所有并发元数据竞争。必须通过独立账户/ACL 禁止不可信主体拥有目标文件、修改其属性（`WRITE_ATTRIBUTES`）或更改其权限；否则不能宣称防止所有硬链接别名带来的副作用。测试保留了这一真实行为，未将其伪装成被共享锁阻断。

相关 Windows 语义参考微软文档：[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)。这些保证依赖正常的 NTFS/内核和服务进程，不能用于防御具有管理员、内核或进程注入能力的攻击者。

## SDK 接入

以下假定管理员已经注册 `files` 工具的能力，独立意图通道已为客户端会话锚定对应请求。示例中的业务目录必须由部署者创建并配置权限。

```python
from adapters.sdk import ICBGuardClient, AuthorizationBlocked, AuthorizationNeedsConfirm

client = ICBGuardClient(token=executor_token)
client.use_capability("files", capability_certificate_id)
# intent_client.anchor_intent(user_prompt, session_id=client.session_id)
result = client.authorize(
    "files", "read_file", "C:/AgentData/report.txt", user_prompt,
)
if result.needs_confirm:
    raise AuthorizationNeedsConfirm(result.confirm_token, result)
if not result.allowed:
    raise AuthorizationBlocked(result.reason, result)
output = client.execute(result)
print(output["content"])
```

审批仍需独立审批身份；获批后携带 `approval_ticket` 对同一动作重新授权，再执行。
HTTP `/execute` 请求结构与旧 `/consume` 相同：`ticket/session_id/tool/action`，响应包含 `status=executed`、`decision_id`、`output`。

`guard` 和 LangChain 包装器在受控模式下只用函数签名绑定参数，不调用本地函数，返回服务端输出字典。这是返回值和执行位置的兼容性变化。建议新接入直接使用 `client.execute()`，避免误以为回调中的其他逻辑仍会运行。SDK 不会在远程执行失败后退回本地执行。

BrowserGym 回调和 pi 内置工具的实际执行位置无法由当前拦截器可靠替换，因此在受控模式拒绝执行。浏览器资源绑定仍待实现，不应把文件执行测试视为浏览器端到端安全验证。

## 部署前提

- 服务运行于专用账户；Agent 账户不能直接读写受保护业务资源，也不能修改服务代码、依赖、环境、策略或密钥。能力声明限制的是请求权限，不能撤销 Agent 在操作系统上已有的权限。
- 本轮代码没有创建系统账户、修改主机 ACL 或安装常驻服务。按同一个用户运行 Agent 和网关，仍不构成操作系统级隔离。
- 服务仅取得所需业务目录权限，不以管理员身份运行。业务数据目录与网关源码目录、`ICB_STATE_DIR` 分开。
- 执行器额外禁止访问网关源码目录、状态目录、独立业务规则文件以及配置的角色凭证文件，即使能力声明过宽也不会经本接口读写这些资源。
- 仍只支持单进程/单 worker；重启后必须重新注册能力和建立会话。

## 故障、审计与验证

执行票据在尝试开始时消耗，成功与失败都不能重复使用。审计记录资源绑定哈希及 `execution_started/completed/failed`，不记录正文。开始前审计失败不会写文件；开始后故障可能产生部分写入，完成审计失败或响应丢失也可能已有完整写入。写入不是崩溃原子事务，不要自动重新授权并重试；先核实文件和审计状态。

回归测试操作临时 NTFS 文件，覆盖真实读写、新建、内容/身份替换、审批资源变更、并发执行、目录改名、硬链接/目录联接、文件竞争、角色校验、撤销及日志失败。没有调用模型或外部业务服务。

```powershell
python -B -m unittest tests.test_controlled_execution -v
```

离线 R-Judge `policy-assisted` 仍是策略辅助判别，不运行本执行器。在线生产网关会额外要求资源实际存在或具备可新建的父目录，未支持动作会拒绝；不能将这种执行覆盖范围差异混同为 benchmark 判别能力提升。
