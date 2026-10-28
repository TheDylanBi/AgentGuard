# ASB：能力说明、可信澄清与任务步骤检查

原生 ASB 的 `run(None)` 返回模拟字符串，不能选择公司、季度、账户，也不能在同一工具中选择“只分析、不调仓”。本项目不把 `portfolio_manager` 改写为已验证的只读工具，不强制调用所有正常工具，不改官方评分。

## 工具能力先与实现相符

每个案例保存 `capability-report.json`，区分目录自述、运维声明和实际接口限制。`business_effect_upper_bound: null` 表示未知，不能按空副作用处理。报告不读取攻击标签，不生成允许名单，也不送回模型作为任务要求。

提供独立的 v2 `--tool-contracts` 后，行动模型和审查模型会看到相同的运维能力说明，包括读取、写入、数据流和所有声明的副作用。规划时仍标记为运维断言；执行时必须核对实际实例、实现和目录指纹。声明不是任务权限，也不能证明实现正确。部署若要求每个工具必须经过独立审阅，另加 `--require-tool-contracts`。

真实工具应暴露独立的、有执行边界的入口，例如读取/分析、修改配置、转账分别注册；也可使用真正受控的操作参数，配合现有 Schema/`SemanticAdapter` 机制。每个操作的能力上界必须覆盖实际效果。仅在描述中写“本次只分析”不能限制兼有交易能力的执行入口。原生 ASB 不具备这一接口，不能在保持原 benchmark 的同时虚构出这些子操作。

## 独立的可信澄清重放

`--task-context` 接受运维方预先取得的用户问答。这是**预置问答重放**，不是模型扮演用户自动编造答案，也不是实时交互界面。文件必须由可信用户入口或人工审阅提供；不能从工具输出、注入内容或评分工具列表生成。

先在项目根目录计算原始请求的绑定值，必须保留原始大小写和标点：

```powershell
& '.\tmp\asb-venv\Scripts\python.exe' -X utf8 -B -c "from attestation.hashing import object_hash; print(object_hash(input('Original task: ')))"
```

文件格式如下。下面的公司和季度只是**虚构示例**，实际使用必须替换为可信用户给出的信息，不能当作原始 ASB 缺失信息的答案。

```json
{
  "version": 1,
  "issuer": "取得用户确认的操作者",
  "reference": "可信用户问答记录编号",
  "tasks": [{
    "request_hash": "sha256:<上述计算得到的64位十六进制值>",
    "clarifications": [{
      "id": "analysis_scope",
      "question": "哪家公司、哪个季度、分析范围是什么？",
      "answer": "ExampleCo，2026年第一季度。仅分析公开公司报告，不读取私人持仓，不交易。"
    }],
    "requirements": [{
      "id": "report_analysis",
      "description": "依据可获得的公开报告分析季度表现；无法取得真实数字时如实说明。"
    }]
  }]
}
```

`requirements` 可为空；其中的项目是用户要求的语义步骤，没有必调工具字段。可信文件本身也可能写错，宿主不会宣称哈希绑定证明了用户同意或语义正确。它只保证本次运行始终使用同一份运维提供的任务上下文。

先用原命令加 `--check` 取得所选 clean 案例 ID。对单个已补充的任务运行：

```powershell
& '.\tmp\asb-venv\Scripts\python.exe' -X utf8 -B -m adapters.asb.run `
  --mode guarded --attack clean --agent financial_analyst_agent `
  --task-num 999 --limit 0 --case-id '从clean检查结果取得的ID' `
  --task-context '.\你的可信问答.json' `
  --tool-schema empty-object --skip-refusal-judge
```

模型服务沿用已有 ASB/AgentDojo 配置。`--skip-refusal-judge` 只跳过额外的拒答模型，原任务和攻击的官方标记评分保留。

文件必须覆盖本次所有选中的不同原始请求。缺少绑定、重复键、超限或非法字段在调用模型前报错，避免同一次实验混入未补充的任务。原始请求保持独立存储，问答同时进入行动模型和审查模型；工具返回始终是不可信观察。执行中变更任务上下文会中止调用，不通过工具文本新增授权。

## 步骤检查与成绩边界

不需要补充用户授权、只想声明交付要求时，使用独立的 `--task-requirements`，不要
伪造一段用户澄清：

```json
{
  "version": 1,
  "issuer": "任务所有者或独立评测规范发布方",
  "reference": "验收标准编号",
  "tasks": [{
    "request_hash": "sha256:<原始请求绑定>",
    "requirements": [
      {"id": "grounded_summary", "description": "给出有来源依据的摘要。"},
      {"id": "missing_data", "description": "如实说明影响结论的缺失信息。"}
    ]
  }]
}
```

该格式禁止工具名和必调工具字段，必须精确覆盖所有选中任务。它不会进入
`CallReviewer.trusted_context`，不会增加用户权限；默认 native 恢复模式下只产生进度和
诊断快照。配合 `--recovery checkpoint` 时，结束检查可以针对这些语义义务提出最多
两个遗漏查询，所有查询仍走原授权入口。模型只可把要求标为有执行证据、证据缺失、
授权阻断或需要澄清；这些状态不是完成真值。

每例的 `task-progress.json` 保存语义要求，以及每次调用是实际执行、被拒还是失败。
执行票据使用 `exec:call-id` 引用。固定字符串只能证明调用返回，不能证明已完成分析，
因此要求始终保留 `not_independently_verified`；checkpoint 评估另列且标记为非真值。
`diagnostics.json` 分开列出语义要求和评分后的正常工具标记覆盖，绝不把后者作为必做步骤。

可选 `--recovery bounded` 在原有次数预算内把这些要求及执行记录交给行动模型检查遗漏。模型仍需经过完整门禁；不重复成功调用，不反复询问有效拒绝，不扩大权限。恢复默认关闭，未证明收益前不自动开启。这里没有独立财务质量裁判，不能把模型自报完成当作成功证明。

不传额外文件时仍是 `asb-native-icb-v1`；传入澄清后为
`asb-trusted-clarification-v1`，仅传语义要求时为 `asb-task-requirements-v1`。
快照和指纹写入结果及比较配置。澄清改变任务权威，不能算作原始 ASB 成绩；语义要求
不改变权威，但仍是不同实验协议。比较器拒绝混用协议或不同上下文。工具拆分同样应
建立独立接口实验，不混入原生40个攻击组合。

可信澄清只能解决确实缺少的用户信息，不能让不相关的持仓操作变得相关，也不能给固定模拟器补出真实报表。是否改善完成率仍需同模型、同配置的 baseline/guarded 对照，并同时检查攻击成功、错误和耗时。
