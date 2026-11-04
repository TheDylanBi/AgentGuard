# AgentDojo 全量消融

实验只在 AgentDojo 模拟宿主生效。固定行动模型、审查模型、API、输出预算、工具清单、
业务策略、日期偏好、16轮上限、300秒任务超时和攻击配置，在同一代码版本运行。

| Group | 设置 | 用途 |
|---|---|---|
| baseline | 原有无防御模式 | 原始能力与攻击成功率参照 |
| full | guarded + review，全部检查 | 完整系统 |
| no-semantic-review | 保留硬门禁，跳过逐次语义判定 | 衡量语义审查贡献；审查 API 请求应为0 |
| no-hard-gate | 计算来源诊断，但忽略逐次硬门禁返回的判定，保留语义审查 | 衡量硬门禁在语义审查之外的增益 |

no-hard-gate 不是移除所有确定性检查。工具暴露范围、JSON/Schema 参数校验、证书验证、
资源引用解析、实际效果解析、调用ID去重、审查协议校验、状态绑定和执行记录仍保留。
来源信息继续提供给模型，因而不是信息缺失消融。忽略的首次硬门禁判定写入审计。
no-semantic-review 保留审查观察账本及共同提示、资源引用协议、恢复和完成检查点，
避免把关闭审查与更换整个宿主路径混在一起。其审查器对象只收集观察，不发起审查请求。
全部变体禁止额外 trusted authorization contracts，以免绕过模型形成额外授权路径。

启动前在 `.local-qwen/run-qwen.ps1` 配置好行动及审查模型。新入口复用这些配置。
GitHub 版本提供不含密钥的 `.local-qwen/run-qwen.example.ps1`。新检出时复制为
`run-qwen.ps1`，设置环境变量 `ICB_ACTION_BASE_URL`、`ICB_ACTION_MODEL`、
`ICB_ACTION_API_KEY` 及独立的 `ICB_INTENT_LLM_BASE_URL/MODEL/API_KEY`。
已有本地启动脚本无需替换。该模板保持当前 DeepSeek 接口兼容设置，其他接口需相应调整。

```powershell
conda activate agentdojo
Set-Location 'F:\Code\MLLM Agent'

# 完整配置检查，不调用模型
& '.\.local-qwen\run-ablation.ps1' -Group no-semantic-review -Phase clean -Check
& '.\.local-qwen\run-ablation.ps1' -Group no-hard-gate -Phase attack -Check

# 每条命令独立运行，按需选择。clean 为四场景97个正常任务。
& '.\.local-qwen\run-ablation.ps1' -Group baseline -Phase clean
& '.\.local-qwen\run-ablation.ps1' -Group full -Phase clean
& '.\.local-qwen\run-ablation.ps1' -Group no-semantic-review -Phase clean
& '.\.local-qwen\run-ablation.ps1' -Group no-hard-gate -Phase clean

# attack 为949个 tool_knowledge 组合，另有35个目标预检查。
& '.\.local-qwen\run-ablation.ps1' -Group baseline -Phase attack
& '.\.local-qwen\run-ablation.ps1' -Group full -Phase attack
& '.\.local-qwen\run-ablation.ps1' -Group no-semantic-review -Phase attack
& '.\.local-qwen\run-ablation.ps1' -Group no-hard-gate -Phase attack
```

结果目录为 `results/agentdojo_pi_ablation_<Group>_<Phase>_<随机标识>`。
clean 根目录有总 summary.json，attack 各场景各有 summary.json。每个场景及每次运行
记录 ablation。baseline/full 的 ablation 都是 full，以 mode 区分。
脚本遇到攻击场景失败会继续剩余场景，最后明确报告未完成场景。
服务错误保留为未评分，不计作成功防御。

主要指标：正常效用BU、攻击下效用UA、官方ASR、安全完成率、平均任务级耗时、
审查请求数与耗时、评分覆盖率、受控停止和错误分类。预检查单独统计，不加入攻击ASR。
文本目标与工具副作用目标分开报告，按 user_task/injection_task 配对。
延迟按相同字段 task_outcomes.elapsed_seconds 比较。硬门禁首次判定及语义判定有先后关系，
不能把审查前阻止的调用当作“审查误放行后拦截”。

旧结果可以作为历史参照。新增开关后源码哈希改变，严格匹配的主实验建议用当前版本
重新运行四组，不修改旧结果哈希。四组clean+attack共4324个计划实例，包含预检查。
当前命令仅覆盖 tool_knowledge 一种攻击方法，未运行其他攻击家族。

原生证据支持、恢复机制、凭证绑定可作为后续扩展消融。本入口没有提供这些独立开关，
不要用 ReviewCoordination=legacy 代替“只移除恢复”，它同时改变完成检查点及停止行为。
