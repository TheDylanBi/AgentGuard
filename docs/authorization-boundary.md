# 初始授权边界与参数分类（2026-10-20）

## 依据与保证范围

参考 [Progent v3](https://arxiv.org/abs/2504.11703v3) 的确定性工具权限检查、区分权限收窄与扩张，以及 [CaMeL v2](https://arxiv.org/abs/2503.18813v2) 的控制流/数据流分离思路。本实现没有复现其完整系统或继承论文的安全证明，也没有加入自动动态扩权。

可靠性边界：程序能检查类型、来源声明、参数覆盖、精确值范围和原有执行限制；不能证明意图模型准确理解了每一句自然语言。运营者声明、工具实现和宿主执行器仍属于信任基础。不要把通过回归测试表述为不存在漏洞或能防住所有注入。

## 使用

```powershell
& '.\.local-qwen\run-qwen.ps1' -IntentFormat boundary -Check
& '.\.local-qwen\run-qwen.ps1' -IntentFormat boundary -UserTask user_task_0
```

`-Check` 只检查配置和工具声明，不调用模型或验证模型输出质量。Python 入口的对应参数是 `--intent-format boundary`。默认仍为 `rules`，以便与旧策略做有控制的比较。baseline 不生成意图边界。

本次已经为 workspace 的全部工具参数添加经过 Schema 绑定的角色声明；它描述工具语义，不依据任务编号或预期答案。未声明角色的新工具保守使用 `control`，仍要求完整参数授权。

## 参数角色

角色在 manifest 的 `tools.<name>.parameter_roles` 中声明，每项必须含 `role` 和审核 `reason`，且工具必须有固定 `schema_hash`。

|角色|含义|本阶段约束|
|---|---|---|
|control|筛选范围、日期、权限级别、附加行为等|有限值或明确来源绑定；不能省略授权|
|resource|读取、创建、修改或分享的资源|有限值或匹配目标字段的来源绑定|
|destination|接收数据或效果的对象|有限值或受控绑定；保留实际收件人、数据流检查|
|content|被存储或传输的文本|明确文本值或获准来源绑定；不允许任意自由文本|
|execution|作为命令、程序等解释执行的内容|初始有限值；拒绝从外部观测绑定可执行内容，旧 rules 模式也不能绕过|

模型不能在授权边界里修改这些角色。不能把目标参数标成 content；普通正文的分类也不豁免 taint、能力和实际效果检查。workspace 的邮件附件包含资源和事件结构，因此仍保守归为 control，没有按文本处理。

## 边界表达

新格式由意图模型在任务开始时生成，输入仅为原始用户请求、工具声明和可信日期等初始上下文，不包含工具结果或行为模型拟议调用。

```json
{
  "version": 1,
  "grants": [{
    "tool": "example_operation",
    "purpose": "完成用户明确要求的操作",
    "parameters": {
      "destination": {"kind": "values", "values": ["user-authorized-target"]},
      "content": {"kind": "unresolved", "reason": "尚无获准的内容来源"}
    }
  }],
  "denies": []
}
```

每个 grant 必须覆盖该工具的全部有效参数，包括默认值。每个参数只能采用以下一种形式：

- `values`：有限备选值，严格检查 JSON 类型。数组参数的备选值是嵌套数组；null 与字符串 "null" 不等价。
- `binding`：`reference` 使用已有 `$binding` 与完整 `source_arguments`；必须匹配声明的目标工具、字段和来源范围。
- `unresolved`：明确缺失的信息或授权。整条 grant 不生成 allow，其他完整的 grant 可以继续；原因保存在快照并反馈给行为模型。

相关联的参数组合必须写成分别完整的 grant，不能依靠各字段备选集合表达关联。`purpose` 和 unresolved 的 reason 是说明，不产生任何权限。`denies` 使用现有 deny DSL；无效 deny 使边界整体失败，不会静默删除。

## 执行链路

初始请求 → 意图边界 → 严格编译 → 既有规则 Schema/语义/效果一致性检查 → 初始规则冻结 → 获准读取及来源绑定 → 原有宿主逐次检查和执行。

编译器输出原有 DSL，保留各 grant 的完整组合，不合并不同授权的字段；未解决参数不转为通配符。边界模式失败不会自动降级到宽松 rules。原有业务禁令、能力约束、参数契约、taint 和效果校验均继续执行。

每次运行的 `policy-*.json` 保存原始 `authorization_boundary`、编译的 `boundary_report` 和最终规则，summary 记录 `intent_format`，供归因和比较使用。

## 当前未解决的问题

自由生成内容仍需要隔离生成器和明确的输入来源/输出用途契约；本阶段没有因为字段叫 content 就放开它。普通文档中的自然语言委托也没有自动成为授权。未知参数若已有适用绑定可以在读取后物化；完全没有获准来源的参数仍会阻塞相应操作，不能仅靠这个格式提高所有任务完成率。

外部模型实测尚未完成；本地测试只能证明所覆盖场景的实现行为。真实比较应固定行为/意图模型、攻击配置及任务集合，分别报告正常完成率、攻击成功率、未评分错误率和拒绝原因。

## 验证记录

- 完整离线 AgentDojo 回归：327 项通过（包含真实 pi SDK 配合本地模拟服务的边界模式执行测试）。
- 最终边界单元测试：8 项通过，其中补充了生成接口的输出格式测试，其余与完整回归重叠，不重复统计。
- 受控执行 26 项、网关安全加固 45 项通过；差异检查通过。
- `--mode guarded --intent-format boundary --check` 返回 configuration_valid，24 个工具、37 个参数。
- 没有调用外部模型；没有修复后的真实任务完成率或攻击成功率结论。
