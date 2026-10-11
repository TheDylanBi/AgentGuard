# ICB-Guard 框架图使用说明

本组图以当前代码为依据，共三张，英文标注，白底、矢量文字、低饱和配色。
PDF 三页依次对应总览、策略细节、票据生命周期。SVG 可独立导入论文制图工具修改。
建议总览用于论文正文的跨双栏插图；细节图用于方法章节或附录，避免把全部细节缩到单栏。

## 文件

- `icb_guard_security_framework.pdf`：三页矢量版。
- `icb_guard_architecture.svg`：框架总览。
- `icb_guard_policy_details.svg`：策略顺序与分支。
- `icb_guard_ticket_lifecycle.svg`：审批、执行消费、撤销与部署边界。
- `icb_guard_preview-1.png` 至 `-3.png`：快速预览。
- `icb_guard_highres-1.png` 至 `-3.png`：3600 像素宽的插图。

## 读图方法

图 1：从上方可信控制平面开始，管理员提供能力上限，可信用户入口锚定意图，
独立审批者处理单次确认。下方从左至右是 agent 动作、视觉证据、签名证据、
策略与行为对齐、网关后处理、三态决策。底部标注状态审计与执行信任前提。

图 2：左侧是策略引擎的实际判定顺序；右侧展开符号谓词、行为对齐、证据融合和 taint。
硬拒绝可以提前返回；CONFIRM/ALLOW 仍会进入适用的 P6 行为对齐检查。
蓝色表示策略与证据检查，绿色表示状态/执行和效应约束，橙色表示审批、条件与边界，红色表示拒绝。

图 3：展示需要审批时的往返，以及直接 ALLOW 的捷径。无论是否审批，
真实执行前都必须消费 execution ticket；消费会重做检查，而后由可信执行器执行。

## 可直接使用的英文图注

**Figure 1.** Architecture of ICB-Guard. Trusted control channels establish administrator-declared
capabilities, session-scoped intent policies, and independent single-action approvals. Agent-proposed
actions pass through evidence collection, signed action binding, deterministic policy checks,
and conditional behavior alignment. The gateway returns BLOCK, CONFIRM, or an execution ticket;
actual execution requires ticket consumption by a trusted adapter.

**Figure 2.** Implemented decision semantics. Hard capability, path, explicit-deny, direct-taint,
and certificate checks precede soft authorization decisions. Symbolic constraints, conditional
effect alignment, and multi-source visual evidence refine the decision. Unknown or incomplete
information is handled explicitly. The figure distinguishes metadata, inferred effects, and enforced checks.

**Figure 3.** Approval and execution lifecycle. Approval is bound to one complete action and does
not expand persistent permissions. One-time execution tickets bind the session, tool, action,
epoch, context, and evidence. Consumption revalidates these bindings and records conservative source
taint before the trusted executor proceeds. Revocation and deployment assumptions are shown separately.

## 与代码的对应关系

| 图中机制 | 实现文件 |
| --- | --- |
| 角色、启动配置、生产 shell 禁用 | `gateway/security.py`, `gateway/config.py`, `gateway/server.py` |
| 工具注册、最新证书、撤销、实现变更 | `policy/capability_registry.py`, `gateway/server.py` |
| 意图规则与效应画像、轮次更新 | `policy/intent_anchor.py`, `gateway/server.py` |
| 主判定顺序、符号约束、路径 | `policy/engine.py`, `policy/symbolic.py`, `policy/paths.py` |
| 条件行为对齐 | `policy/authorize.py`, `policy/effect_model.py`, `policy/behavior_alignment.py` |
| 视觉证据与多源融合 | `gateway/server.py`, `fusion/consensus.py`, `verifiers/` |
| 审批及消费、状态更新 | `gateway/server.py` |
| 敏感数据来源与外流检查 | `policy/taint.py` |
| 签名与审计链 | `attestation/signer.py`, `attestation/log.py` |
| 可信适配器执行 | `adapters/sdk.py`, `adapters/langchain.py`, `adapters/browser_gym.py`, `adapters/pi_extension.ts` |

## 准确性说明

这些图没有把尚未实现的独立沙箱、多租户权限、通用参数约束执行、完整数据流追踪、
实际二进制测量或外部审计检查点画成现有保护。R-Judge 判别模型不属于在线授权链路。
签名证明来源与完整性，不等于动作本身安全。图中“actual effects”来自参数提取，
因此统一使用“extracted effects”，避免暗示执行后观测。

注意：部分旧代码注释称 P6 在引擎之前运行；本图依据当前 `authorize_action()` 的实际调用顺序绘制。
