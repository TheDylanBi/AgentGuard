# ICB-Guard 当前安全框架图

基于 2026-10-23 工作区中已实现的 `guarded / review` 路径绘制。采用论文常用的白底、有限配色、模块分组、信任边界和反馈回路；未复刻某篇论文的原图。

## 文件

- `output/pdf/icb_guard_current_framework_zh.pdf`：中文，两页矢量图。
- `output/pdf/icb_guard_current_framework_en.pdf`：英文，两页矢量图。
- `output/figures/current_framework/icb_guard_architecture_{zh,en}.{svg,png}`：整体架构。
- `output/figures/current_framework/icb_guard_decision_protocol_{zh,en}.{svg,png}`：逐次授权与恢复协议。
- SVG 保留文字对象，方便在矢量编辑器中修改；中文使用微软雅黑，英文使用 Arial。PDF 嵌入字体，适合直接插入论文。PNG 为 3240 × 2232 像素。

## 阅读方式

图 (a) 从原始用户请求开始，行动模型选择工具并生成参数。可信宿主解析资源引用并检查原生 Schema，执行独立硬边界检查，再由独立上下文中的审查模型判断具体操作的任务授权。通过后复核状态，将决定绑定到具体工具、完整有效参数、调用 ID 和相关状态，再由宿主执行。工具返回数据以不可信内容进入来源台账和证据状态，不得改写原始授权。

图 (b) 展开 `allow / deny / needs_evidence` 的不同后果。格式错误、规划偏差、证据不足和安全边界冲突分开反馈；补证操作仍需逐次检查。技术失败保持关闭执行，并与真实安全拒绝分别统计。程序构造结构性哈希字段，不能替模型补出授权决定。

颜色：蓝色表示检查与可信配置，绿色表示证据及受控执行，琥珀色表示有限恢复，红色表示可能包含注入的数据或拒绝路径。箭头颜色以流向所表示的内容为准；琥珀色虚线是反馈，不是授权。

## 图中模块与代码

| 图中模块 | 主要实现 |
| --- | --- |
| pi 行动模型、任务锚点、桥接与审查编排 | `adapters/agentdojo_pi/pipeline.py` |
| 序列化检查和原生受控执行 | `adapters/agentdojo_pi/host.py` |
| RID 精确身份解析与有效期检查 | `policy/resource_handles.py` |
| 独立硬边界 | `policy/authorize.py`, `policy/engine.py` |
| 工具声明与规范化语义动作 | `policy/semantic_action.py` |
| 审查协议、短证据引用及单次纠正 | `policy/call_review.py` |
| 资源与参数来源 | `policy/resource_provenance.py`, `policy/argument_provenance.py`, `policy/parameter_evidence.py` |
| 数据使用范围与类型化证据 | `policy/data_use.py`, `policy/typed_evidence.py` |
| 有界恢复 | `policy/action_feedback.py` |
| 执行进度与回答校验 | `policy/execution_progress.py`, `policy/answer_arithmetic.py` |

## 保证范围

- RID 只代表精确资源身份，EID 只代表证据引用；二者均不是授权凭据。
- 来源验证和算术推导不自动证明任务授权。审查同意也不清除污染或覆盖独立业务规则。
- 工具声明描述能力和可能副作用的上界，不等于观测结果，也不证明工具实现正确。
- 独立审查指分离的审查过程与上下文，不保证采用不同模型权重。
- 当前资源引用需要可信工具声明接入，不能宣称任意工具无需适配即可获得全部保证。
- 完成检查核对已执行操作与回答，不是通用的完整任务证明。
- 此图聚焦当前 review 路径。保留的 `rules / boundary` 对照模式以及无防护的 `baseline` 没有混入主流程；图也未表示新增了任务特例或默认业务禁令。

## 重新生成与检查

在项目根目录运行：

```powershell
& 'D:/miniconda3/envs/mllm/python.exe' -X utf8 -B docs/figures/draw_current_framework.py
```

生成器需要 matplotlib。若项目临时目录 `tmp/pdfs/render_deps` 中有 pypdfium2，会额外从最终 PDF 渲染每页 PNG 以检查字体与布局；`layout_checks.json` 保存文字越界检查。绘图过程不调用模型、不运行 benchmark、不改变安全策略或服务配置。

建议图注：ICB-Guard 的逐次语义授权架构。行动模型提出工具调用，可信宿主校验身份、能力、来源与数据流边界；独立审查器依据原始请求和宿主证据判断任务授权。批准绑定具体调用和状态，由宿主复核并执行，拒绝及证据不足通过有限反馈回路恢复。

English caption: ICB-Guard per-call semantic authorization. An action model proposes tool calls; a trusted host enforces identity, capability, provenance, and data-flow boundaries. An independent reviewer judges task authorization using the immutable request and host-maintained evidence. Approval is bound to the exact call and relevant state before host-side execution, while denials and missing evidence trigger bounded feedback.
