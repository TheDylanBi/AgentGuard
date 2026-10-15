# 声明驱动的工具接入与动态绑定

本机制把“工具允许做什么”和“任务执行后才能知道哪个对象”分开。通用实现位于 `policy/runtime_bindings.py`；当前观测与执行接线位于 AgentDojo 的 `SimulationHost`。模型不能通过工具结果新增权限，原始任务规则不被修改。

## 接入新工具

1. 在 runtime 注册工具及参数 schema，并在可信 manifest 中声明能力、效应、目标字段和 schema 哈希。所有参数仍通过工具参数契约检查。
2. 审核哪些源工具结果可以用于哪个目标工具字段，在 manifest 顶层 `bindings` 中声明用途。声明不是任务授权。
3. 意图阶段必须为该目标工具生成明确 allow 模板，并引用声明。没有模板的工具仍会被拒绝。
4. 主机只采集已授权且执行成功的工具结果，生成任务内绑定。模型仍需提交具体参数；主机不会偷偷修改调用。
5. 每次调用重新检查能力硬约束、业务规则、意图、taint、效应和完整参数契约，通过后才执行。

例如两个新工具 `custom_lookup(query)` 和 `custom_use(record_id)`，前者返回 `[{"id":"R1"}]`：

```json
{
  "bindings": {
    "selected_record": {
      "source_tool": "custom_lookup",
      "source_path": ["*", "id"],
      "source_arguments": {"query": "report"},
      "target_tool": "custom_use",
      "target_field": "record_id",
      "ttl_seconds": 60,
      "max_uses": 1,
      "reason": "操作方审核：仅使用授权查询返回的唯一记录"
    }
  }
}
```

初始任务规则中必须另有源查询的授权，以及如下目标模板：

```json
{
  "tool": "custom_use",
  "decision": "allow",
  "predicate": {
    "op": "eq",
    "field": "payload.record_id",
    "value": {"$binding": "selected_record"}
  }
}
```

源查询必须同时满足任务规则与 `source_arguments` 的精确类型匹配。空 `source_arguments` 表示不增加查询条件，不会跳过任务授权。引用只能位于正向 `eq` 或其 `and` 中，不能放在 `or`、`not`、deny 内。目标其他参数也必须各自有授权。

## 安全边界与保守限制

- 路径只支持对象键与列表 `*`；必须恰好提取一个值，即使两个对象返回相同 ID 也不猜测。严格验证目标类型，不作隐式转换。
- 绑定隔离于任务，记录来源调用、环境哈希、值哈希，并限定有效期和使用次数。重复观测使绑定失效，不能靠重复查询刷新有效期。
- 当前检查整个模拟环境的哈希；无关对象的变化也可能使绑定失效。这比对象级版本检查更保守。
- 绑定不清除 taint、不绕过 deny 或能力参数上限、不自动批准 CONFIRM，也不授权额外工具。
- 默认 workspace 只配置 `search_files_by_filename → get_file_by_id` 的唯一文件读取绑定；不会自动新增删除、分享、发送权限。
- 操作方必须审核源字段的语义与真实性。类型正确的返回值不等于可信对象身份；任意第三方 API 的生产资源身份和原子执行保障，不由模拟环境哈希证明。
- 不支持任意自然语言结果自动推导权限；多对象选择、复杂日期、跨状态操作仍需要更明确的可信选择规则。

日期是另一类上下文绑定：在工具项声明 `"context_bindings":{"report_day":{"kind":"user_date","reason":"审核依据"}}`。声明字段必须存在并固定 schema 哈希。目前只处理每个工具单一日期字段，从用户原文和公开模拟时钟解析唯一日期，以 AND 收紧已有规则。

## 拒绝后的恢复与审计

可修复的参数问题返回结构化建议；同一问题最多两次修正，原样重复或耗尽预算停止工具执行。终止后最多有一次无工具的最终回答，保留所有被拒提议。`answered_after_stop` 不表示任务成功，仍由官方 checker 判分。

`audit/policy-*.json` 保存初始规则覆盖报告和绑定声明；执行审计记录实际使用的绑定来源，运行统计记录观测及消耗。覆盖报告只提示没有授权或参数未约束，不自动补发权限。

## 普通生产 pi 扩展

普通 `adapters/pi_extension.ts` 可从环境变量 `ICB_PI_TOOL_MAPPINGS` 指定的可信 JSON 文件加载额外工具映射，例如：

```json
{"custom_reader":{"action_type":"read_file","target_field":"path"}}
```

扩展安装时读取一次。映射不能覆盖保留的内置工具；所有原参数继续提交网关，能力证书仍须覆盖该动作。受控执行模式不因此允许任意本地工具回调。

此映射解决工具名称接入，不等于生产动态观测绑定：生产网关没有自动采集第三方工具结果来生成上述 `$binding`。生产执行继续使用原有能力、审批、票据和受控执行器边界。

## 论文启发及验证口径

[Lost in Implicit Routing: How LLM Agents Fail to Load Relevant Skills at Scale](https://arxiv.org/pdf/2610.18522) 研究大量技能下的隐式选择遗漏，提示可以把选择覆盖诊断与执行分开。本实现据此增加规则覆盖诊断，没有把预选工具等同于授权，也没有引入论文的预选算法。它不能证明本项目先前的失败原因，也不能作为动态授权安全性的证明。

本地测试覆盖全新工具声明接入、真实 workspace 文件读取、过期、跨任务、环境变化、多结果、错误类型、deny、能力硬约束，以及真实 pi SDK 的无工具最终回答。测试模型为本地可控响应；这些结果不等于远程模型或完整 AgentDojo 的成绩。
