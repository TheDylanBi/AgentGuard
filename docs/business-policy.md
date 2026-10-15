# 独立业务安全规则

默认没有业务禁令。未设置配置文件时加载空规则，不改变原有能力、意图、taint 等检查。
管理员可以按业务增加限制；用户意图、客户端画像和人工审批都不能解除这些限制。

## 配置与生效

将 JSON 文件放到由网关管理员控制、Agent 无法修改的目录，设置：

```powershell
$env:ICB_BUSINESS_POLICY_FILE = "C:/ICBGuardState-v2/business-policy.json"
```

生产模式要求路径位于 Agent 工作区外；实际 ACL/账号隔离仍需部署者设置。
使用 `docs/examples/business-policy.empty.json` 可创建空配置。配置文件由每个策略引擎
在初始化时加载一次；设置或修改后必须重启网关。重启也使原有内存会话和票据失效。
不支持热更新，避免文件内容在一次授权流程中发生不明确的变化。

显式指定的文件不存在、JSON 格式错误、键重复、规则格式不支持时，启动失败，
不会降级为空规则。文件最大1 MiB，最多256条规则。

## 支持的两种规则

下面只是格式演示，不会默认启用，也不代表已经确定了业务限制：

```json
{
  "version": 1,
  "rules": [
    {"id": "disable-export", "actions": ["export_records"], "mode": "deny"},
    {
      "id": "transfer-boundary",
      "actions": ["transfer"],
      "mode": "require",
      "parameter_constraints": {
        "amount": {"type": "number", "minimum": 0, "maximum": 100},
        "recipient": {"type": "string", "enum": ["approved-account"]}
      }
    }
  ]
}
```

- `actions` 匹配真实 `action.type`，不是显示名称或 tool_id；`["*"]` 匹配所有动作。
  除单独的 `*` 外不支持通配符。管理员应覆盖所有具有同类业务效应的动作名称。
- `deny` 无条件硬拒绝命中的动作，不允许附加参数条件以免误解语义。
- `require` 强制动作满足非空的参数约束，字段规则见 `parameter-constraints.md`。
  缺少必填值、越界或类型错误均 BLOCK。
- 多条命中的规则取交集，不能被后续规则放宽；没有 allow/审批例外机制。
- 通过这些规则仅表示未被它们拒绝，仍需通过能力、意图、证据、taint 等其余检查。

业务检查位于策略引擎入口，早于意图规则。`/consume` 重做授权时同样检查。
拒绝标识为 `business.<规则ID>`；已加载规则的 SHA-256 进入决策审计与票据上下文绑定。
修改用户请求、重新锚定意图、批准单次动作均不能覆盖业务硬拒绝。

## 评测

在线网关使用服务端配置。离线 `policy-assisted` 必须显式指定文件：

```powershell
python -B demo/attacks/replay_rjudge_symbolic.py --protocol policy-assisted --expected-count 571 --business-policy C:/ICBGuardState-v2/business-policy.json
```

一次评测只加载一次文件，结果记录规则哈希。未传此参数时仍是空业务规则；
不自动读取服务端环境变量，避免 baseline 或离线实验偷偷变更。
`official` 模式不支持此参数。原有动作解析覆盖率限制仍存在。

## 本次没有实现或默认设置的内容

没有自动决定敏感数据分类、合法收件人、金额上限或用户权限。
没有累计额度、跨会话交易记账、多租户绑定、域名网络隔离、内容危害分类器。
单笔金额条件不能被解释为每日总额度；参数比较也不能替代真实业务身份核验。

在确定具体业务规则前，需要提供：动作与参数清单、允许/禁止对象、数据分类、
单次与累计额度要求，以及哪些约束必须不可审批覆盖。
