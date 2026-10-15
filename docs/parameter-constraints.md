# 能力参数硬约束

管理员在 `/register_tool` 的 `declared_capabilities.parameter_constraints` 中配置。
声明随 capability 证书签名。该约束在策略引擎入口检查，优先于意图规则，
违反时返回 `BLOCK`，规则标识 `capability.parameters`。审批只能覆盖 CONFIRM，
所以不能放宽此边界。`/consume` 重做授权时也会重查。

```json
{
  "amount": {"type": "number", "minimum": 0, "maximum": 100},
  "currency": {"type": "string", "const": "CNY"},
  "recipients": {
    "type": "array", "minItems": 1, "maxItems": 2,
    "items": {"type": "string", "enum": ["alice@example.test", "bob@example.test"]}
  },
  "payload.payment.account": {"type": "string", "enum": ["account-a"]},
  "note": {"type": "string", "maxLength": 200, "required": false}
}
```

这只是格式示例；字段必须与真实工具收到的参数一致。现有工具声明中的空字典
仍然有效，但不会凭空产生金额或收件人限制。更新已注册工具需要管理员重新注册，
旧证书会被撤销，执行方需要使用新证书 ID。

## 支持的语义

| 配置 | 语义 |
| --- | --- |
| `amount` | payload 顶层的 amount，与 `payload.amount` 等价；重复别名拒绝注册 |
| `payload.payment.amount` | 逐层查找嵌套字典；不把带点的扁平键当作嵌套字段 |
| `target` | 动作的 target；payload 中同名字段请写 `payload.target` |
| `type` | string / number / integer / boolean / array |
| `enum` / `const` | 有限标量允许值 / 单一固定值，严格比较；不解码、不改大小写 |
| `minimum` / `maximum` | 含边界数值限制；可以不写 type，此时仍要求有限数值 |
| `exclusiveMinimum` / `exclusiveMaximum` | 不含边界的数值限制 |
| `minLength` / `maxLength` | 字符串字符数；必须显式指定 string |
| `minItems` / `maxItems` | 数组元素数；必须显式指定 array |
| `items` | 每个数组元素必须满足子约束；必须显式指定 array |
| `required` | 默认 true；false 只允许缺失，不允许错误类型或越界值 |

所有字段约束、同一字段的所有条件按 AND 组合。
数值不接受 bool、数字字符串、NaN、Infinity。integer 不接受 1.0。
枚举中 true 与 1 不等价。字符串允许值为精确比较，不提供域名、邮箱或 URL 的语义解析。
若要约束 URL，使用经过业务确认的精确 URL 允许值；不要把它称为网络层域名隔离。

可选嵌套字段缺失时可通过；父字段已存在但不是字典则拒绝。不支持数组下标路径或通配路径，
数组约束使用 items。每份声明最多128个字段，字段名最多256字符，枚举最多1024个值，
items 最多8层递归。字段名采用 ASCII 字母、数字、下划线和连字符，每段不能以数字开头。

## 故障行为与范围

- 未知键（例如 format、pattern、$ref、properties）拒绝注册，不会静默忽略。
- 空规则、非法类型、非法数值、相反上下界拒绝注册；空 parameter_constraints 表示不添加参数限制。
- 离线直接调用引擎时同样校验约束，非法声明返回 BLOCK。
- 缺失参数不由网关猜测默认值：SDK 会绑定函数默认参数，再提交完整参数供检查。
- 边界错误信息包含字段名与失败类型，不回显实际参数值。
- 这是每次调用的约束，不是跨请求累计预算、完整 JSON Schema 或业务身份验证。
- 约束只能覆盖正确声明并实际提交的参数；仍依赖可信适配器、工具实现与资源隔离。

## 验证

```powershell
python -B -m unittest tests.test_parameter_constraints tests.test_security_hardening tests.test_rjudge_evaluation
```

覆盖数值边界、类型混淆、空值、缺失参数、精确收件人、数组所有元素、嵌套字段、
非法注册 HTTP 422、意图不可扩权、审批不可覆盖，以及消费时重复检查。
