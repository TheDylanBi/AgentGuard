"""Draw the implemented review architecture; export editable SVG and vector PDF.

Requires matplotlib. Optional PDF render validation uses pypdfium2 from
tmp/pdfs/render_deps. No model calls or runtime configuration changes.
"""
from pathlib import Path
import json
import os
import sys

os.environ.setdefault("MPLCONFIGDIR", str(Path(__file__).resolve().parents[2] / "tmp" / "pdfs" / "mplconfig"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.font_manager import FontProperties
from matplotlib.backends.backend_pdf import PdfPages

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output" / "figures" / "current_framework"
PDF_OUT = ROOT / "output" / "pdf"
OUT.mkdir(parents=True, exist_ok=True)
PDF_OUT.mkdir(parents=True, exist_ok=True)
matplotlib.rcParams.update({"svg.fonttype": "none", "pdf.fonttype": 42,
                           "font.family": "Arial", "savefig.facecolor": "white"})
W, H = 1800, 1240
C = {"ink": "#172C40", "muted": "#586877", "blue": "#346387",
     "bluebg": "#F0F5FA", "teal": "#24796E", "tealbg": "#EFF8F5",
     "amber": "#996D28", "amberbg": "#FCF7EC", "red": "#A54C52",
     "redbg": "#FCF1F2", "gray": "#A5B2BF", "graybg": "#F6F8FA",
     "white": "#FFFFFF"}
CHECKS = []


class Figure:
    def __init__(self, lang, name):
        self.lang, self.name = lang, name
        self.fig = plt.figure(figsize=(18, 12.4), dpi=120)
        self.ax = self.fig.add_axes((0, 0, 1, 1))
        self.ax.set(xlim=(0, W), ylim=(H, 0))
        self.ax.axis("off")
        self.texts = []
        self.zfont = FontProperties(fname="C:/Windows/Fonts/msyh.ttc")

    def t(self, en, zh):
        return zh if self.lang == "zh" else en

    def box(self, x, y, w, h, tone="blue", dashed=False, fill=True, lw=1.3):
        p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=7",
            edgecolor=C[tone], facecolor=C.get(tone + "bg", "white") if fill else "white",
            linewidth=lw, linestyle=(0, (5, 4)) if dashed else "solid", zorder=1)
        self.ax.add_patch(p)

    def text(self, x, y, s, size=22, tone="ink", bold=False, va="top", ha="left"):
        kw = {"fontproperties": self.zfont} if self.lang == "zh" else {}
        a = self.ax.text(x, y, s, fontsize=size * .72, color=C[tone],
            weight="bold" if bold else "normal", va=va, ha=ha,
            linespacing=1.5, zorder=5, **kw)
        self.texts.append(a)
        return a

    def card(self, x, y, w, h, title, lines, tone="blue", number=None,
             body_size=22, line_step=37):
        self.box(x, y, w, h, tone)
        title_y = y + 23
        if number:
            self.text(x + 20, y + 20, number, 21, tone, True)
            title_y += 31
        self.text(x + 20, title_y, title, 26, "ink" if tone == "gray" else tone, True)
        yy = title_y + 90 if "\n" in title else title_y + 48
        for line in lines:
            artist = self.text(x + 20, yy, line, body_size)
            artist._card_bounds = (x + 14, y + 10, x + w - 14, y + h - 5)
            yy += line_step * (line.count("\n") + 1)

    def arrow(self, points, tone="blue", dashed=False, both=False, width=1.7):
        for a, b in zip(points[:-2], points[1:-1]):
            self.ax.plot((a[0], b[0]), (a[1], b[1]), color=C[tone], lw=width,
                         ls=(0, (5, 4)) if dashed else "solid", zorder=3)
        a, b = points[-2:]
        self.ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>",
            mutation_scale=13, color=C[tone], lw=width,
            linestyle=(0, (5, 4)) if dashed else "solid", shrinkA=0, shrinkB=0, zorder=3))
        if both:
            self.ax.add_patch(FancyArrowPatch(points[1], points[0], arrowstyle="-|>",
                mutation_scale=13, color=C[tone], lw=width, shrinkA=0, shrinkB=0, zorder=3))

    def header(self, letter, title, subtitle):
        self.text(42, 30, "ICB-GUARD", 21, "blue", True)
        self.text(1758, 30, letter, 19, "muted", True, ha="right")
        self.text(42, 70, title, 36, "ink", True)
        self.text(42, 122, subtitle, 21, "muted")

    def footer(self, text):
        self.ax.plot((42, 1758), (1180, 1180), color=C["gray"], lw=.8)
        self.text(42, 1196, text, 19, "muted")

    def export(self, pdf):
        self.fig.canvas.draw()
        renderer = self.fig.canvas.get_renderer()
        inverse = self.ax.transData.inverted()
        overflow = []
        for a in self.texts:
            bb = a.get_window_extent(renderer).transformed(inverse)
            if bb.x0 < 0 or bb.x1 > W or bb.y0 < 0 or bb.y1 > H:
                overflow.append(a.get_text())
            if hasattr(a, "_card_bounds"):
                x0, y0, x1, y1 = a._card_bounds
                if bb.x0 < x0 or bb.x1 > x1 or min(bb.y0, bb.y1) < y0 or max(bb.y0, bb.y1) > y1:
                    overflow.append(a.get_text())
        CHECKS.append({"figure": self.name, "language": self.lang,
                       "text_count": len(self.texts), "overflow": overflow})
        if overflow:
            raise ValueError(f"Text overflow in {self.name}/{self.lang}: {overflow}")
        stem = OUT / f"{self.name}_{self.lang}"
        self.fig.savefig(stem.with_suffix(".svg"), format="svg")
        self.fig.savefig(stem.with_suffix(".png"), dpi=180)
        pdf.savefig(self.fig)
        plt.close(self.fig)


def architecture(lang):
    f = Figure(lang, "icb_guard_architecture")
    t = f.t
    f.header("(a)", t("Runtime-enforced per-call semantic authorization", "逐次语义授权与宿主强制执行"),
        t("Current review mode: immutable intent, independent review, exact-call enforcement.",
          "当前 review 模式：保留原始意图，独立审查每次调用，由宿主落实执行约束。"))
    f.card(42, 175, 558, 117, t("Trusted task anchor", "可信任务锚点"),
        [t("Original request + trusted context; immutable", "原始请求与可信上下文；工具结果不得改写")], "blue", body_size=22)
    f.card(626, 175, 1132, 117, t("Operator-controlled declarations", "运维方可信声明与配置"),
        [t("Pinned tool Schema / capabilities / scopes / business rules / source & effect contracts",
           "绑定工具 Schema、能力范围、独立业务规则、来源与副作用上界；通过声明接入新工具")], "blue", body_size=22)
    f.box(342, 340, 1416, 421, "blue", dashed=True, fill=False)
    f.text(362, 355, t("TRUSTED HOST: CHECKS AND EXECUTION", "可信宿主：检查与受控执行"), 21, "blue", True)
    f.text(1735, 356, t("model output alone cannot execute", "模型输出本身不能执行"), 19, "muted", ha="right")
    f.arrow([(185, 292), (185, 406)])
    f.arrow([(520, 292), (520, 316), (1221, 316), (1221, 406)])
    f.arrow([(874, 292), (874, 340)])
    f.card(42, 406, 268, 310, t("Action model\n(pi worker)", "行动模型\n（pi 独立 worker）"), [
        t("Plan the next operation", "规划下一步操作"),
        t("Choose tool + args", "选择工具并生成参数"),
        t("Proposals are untrusted", "调用提案不构成授权"),
        t("Separate review context", "与审查器分离上下文")], "gray", body_size=21, line_step=34)
    titles = [("Resolve & validate", "引用解析与校验"), ("Hard boundaries", "独立硬边界检查"),
              ("Semantic review", "独立语义授权审查"), ("Bind & execute", "绑定与受控执行")]
    content = [
        [("Proposal integrity", "提案身份与哈希一致性"), ("RID -> exact native identity", "RID → 精确原生身份"),
         ("Task / scope / TTL checks", "任务、范围、有效期检查"), ("Schema, types & defaults", "Schema、类型与默认值"),
         ("Complete effective arguments", "得到完整有效参数")],
        [("Tool identity & capability", "工具认证与能力约束"), ("Business & resource limits", "业务规则与资源边界"),
         ("Sources / recipients / taint", "来源、收件人与污染流"), ("Declared effect upper bounds", "声明的副作用能力上界"),
         ("PASS != task authorization", "通过 ≠ 已获任务授权")],
        [("Intent + normalized action", "原始意图与规范化动作"), ("Full arguments + evidence", "完整参数与必要来源证据"),
         ("Prior execution + data use", "执行记录与数据使用目的"), ("allow / deny\nneeds_evidence", "allow / deny\nneeds_evidence"),
         ("No replacement args or code", "不代写替换参数或代码")],
        [("Recheck limits & freshness", "复核硬边界与状态新鲜度"), ("Bind tool / args / state / ID", "绑定工具、参数、状态及 ID"),
         ("One call; no persistent rights", "单次使用；不授予永久权限"), ("Native host-side dispatch", "宿主派发原生工具调用"),
         ("Observe results & changes", "记录结果与实际状态变化")]
    ]
    for i, x in enumerate((362, 710, 1058, 1406)):
        f.card(x, 406, 326, 310, t(*titles[i]), [t(*s) for s in content[i]],
               "teal" if i == 3 else "blue", number=f"0{i+1}", body_size=21, line_step=33)
    for x0, x1 in ((310, 362), (688, 710), (1036, 1058), (1384, 1406)):
        f.arrow([(x0, 556), (x1, 556)])
    f.card(42, 822, 268, 191, t("Bounded recovery", "有界反馈与恢复"), [
        t("Field-specific feedback", "反馈原因与相关字段"),
        t("Replan / get evidence", "重规划或补充证据"),
        t("Stop when budget ends", "预算耗尽则受控终止")], "amber", body_size=21, line_step=33)
    f.arrow([(342, 736), (326, 736), (326, 1033), (176, 1033), (176, 1013)], "amber", True)
    f.arrow([(290, 822), (290, 716)], "amber", True)
    f.text(49, 779, t("feedback, not a grant", "反馈不等于授权"), 20, "amber")
    f.card(362, 822, 440, 191, t("Identity & provenance ledger", "身份与来源证据台账"), [
        t("RID: exact resource identity", "RID：精确资源身份"),
        t("EID: packet evidence reference", "EID：审查证据引用"),
        t("Account / snapshot / source hashes", "账户、快照与原始结果哈希")], "teal", body_size=21, line_step=33)
    f.card(827, 822, 440, 191, t("Evidence & data-flow state", "证据图与数据流状态"), [
        t("Typed facts + bounded arithmetic", "类型化事实与有界算术推导"),
        t("Nested taint + scoped data use", "嵌套污染跟踪与限定数据使用"),
        t("Read coverage + execution receipts", "读取覆盖记录与执行回执")], "teal", body_size=21, line_step=33)
    f.card(1292, 822, 440, 191, t("Tool environment / results", "工具环境与返回数据"), [
        t("AgentDojo simulated native tools", "AgentDojo 原生模拟工具"),
        t("Contents may contain injection", "返回内容可能包含注入指令"),
        t("Data cannot expand task authority", "数据不能自行扩展用户授权")], "red", body_size=21, line_step=33)
    f.arrow([(525, 822), (525, 716)], "teal")
    f.text(372, 785, t("RID binding", "精确身份绑定"), 19, "teal")
    f.arrow([(1115, 822), (1115, 785), (1221, 785), (1221, 716)], "teal")
    f.text(857, 780, t("host-built review evidence", "宿主构造审查证据"), 19, "teal")
    f.arrow([(1545, 716), (1545, 822)], "blue")
    f.arrow([(1640, 822), (1640, 716)], "red")
    f.text(1397, 781, t("call", "调用"), 19, "blue")
    f.text(1680, 781, t("result", "结果"), 19, "red")
    f.arrow([(1292, 930), (1267, 930)], "teal")
    f.card(42, 1062, 1060, 110, t("Signed audit trail", "签名审计记录"), [
        t("Raw proposal -> RID mapping -> native arguments -> decision -> state & execution receipt",
          "原始提案 → 引用映射 → 原生参数 → 授权决定 → 状态与执行回执；保留拒绝和错误记录")], "gray", body_size=21)
    f.card(1127, 1062, 631, 110, t("Once-only completion checkpoint", "单次任务结束检查"), [
        t("Reconcile receipts & answer; no universal task proof", "核对回执与回答；不代表通用的完整任务证明")], "gray", body_size=21)
    f.footer(t("RID != EID != authorization   |   Source verified != task authorized   |   Declared effects != observed effects",
               "RID ≠ EID ≠ 执行授权    |    来源可信 ≠ 任务已授权    |    声明效果上界 ≠ 已观测执行效果"))
    return f


def protocol(lang):
    f = Figure(lang, "icb_guard_decision_protocol")
    t = f.t
    f.header("(b)", t("Authorization, evidence and bounded recovery", "单次授权、证据补全与有界恢复协议"),
        t("The host enforces structure and execution; the reviewer judges task semantics.",
          "宿主负责结构、来源与执行约束；审查器负责判断该次动作是否符合用户授权。"))
    f.card(42, 181, 542, 225, t("1  Build the semantic action", "1  构造规范化语义动作"), [
        t("Operation + resource + destination", "操作类别、资源与目的地"),
        t("Data sources + content + parameter roles", "数据来源、内容与参数角色"),
        t("Declared side-effect / capability upper bound", "可信声明限定的副作用与能力上界"),
        t("Tool name binds execution, not a task allow-list", "工具身份用于执行绑定，不预测工具白名单")], "blue", body_size=23, line_step=33)
    f.card(629, 181, 545, 225, t("2  Bind evidence to this exact call", "2  为本次调用构造审查证据"), [
        t("Immutable request + full effective arguments", "原始请求与完整有效参数"),
        t("Host observations + prior execution receipts", "宿主观察、来源事实与已执行操作"),
        t("Short EID references + explicit data_use_scope", "短 EID 引用与本次 data_use_scope"),
        t("Actor explanations / tool instructions: untrusted", "行动模型解释与工具内指令不构成授权")], "teal", body_size=23, line_step=33)
    f.card(1219, 181, 539, 225, t("3  Validate minimal reviewer output", "3  校验最小化审查输出"), [
        t("Decision + reason code + fields + evidence IDs", "结论、原因类别、相关字段、证据引用"),
        t("Explicit data-use decision when required", "需要时显式判断数据使用是否获授权"),
        t("Host fills hashes only after a valid decision", "有效判断后由程序填充哈希与绑定字段"),
        t("No confidence threshold or replacement code", "不用自报置信度；不生成替换参数或代码")], "blue", body_size=23, line_step=33)
    f.arrow([(584, 292), (629, 292)], "teal")
    f.arrow([(1174, 292), (1219, 292)], "teal")
    f.text(42, 449, t("Review decision", "审查结果分支"), 23, "ink", True)
    columns = (42, 629, 1219)
    f.card(columns[0], 500, 542, 239, "ALLOW", [
        t("Hard checks + state freshness pass again", "再次通过硬检查与状态新鲜度校验"),
        t("Bind exact tool / native args / state / call ID", "绑定确切工具、原生参数、状态与调用 ID"),
        t("Single host dispatch -> record actual effects", "仅派发一次，记录真实执行结果与变化"),
        t("Cannot clear taint or override business limits", "不能清除污染或覆盖独立业务禁令")], "teal", body_size=23, line_step=38)
    f.card(columns[1], 500, 545, 239, "NEEDS_EVIDENCE", [
        t("Name missing source / resource / task evidence", "区分来源、资源绑定与任务授权证据缺口"),
        t("Feedback -> actor proposes prerequisite action", "反馈行动模型，由其规划必要的补证操作"),
        t("Prerequisite calls require their own checks", "补证调用也必须独立通过安全检查"),
        t("New evidence may support a new scoped call", "新证据可支持下一次有界、具体的审查")], "amber", body_size=23, line_step=38)
    f.card(columns[2], 500, 539, 239, "DENY", [
        t("Reject this specific call; cite category / fields", "拒绝该具体调用，反馈原因类别与字段"),
        t("Bounded replan within original authorization", "在原始授权内进行有限重规划"),
        t("Never retry a valid denial to fish for approval", "不通过重复询问审查器争取放行"),
        t("New authority requires trusted confirmation", "扩大授权必须获得可信确认")], "red", body_size=23, line_step=38)
    f.arrow([(1490, 406), (1490, 434), (313, 434), (313, 500)], "teal")
    f.arrow([(1490, 434), (902, 434), (902, 500)], "amber")
    f.arrow([(1490, 434), (1490, 500)], "red")
    f.card(42, 793, 836, 229, t("Technical failure is not a security decision", "技术失败不能冒充安全决策"), [
        t("Malformed structure -> at most one corrective retry", "结构错误：最多一次技术性纠正重试"),
        t("Timeout / truncation / invalid output / oversized evidence", "超时、截断、持续无效输出或证据包超限"),
        t("Fail closed; record a model-stage error / unscored task", "保持关闭执行；记录模型阶段错误与未评分任务"),
        t("Do not synthesize allow or count the error as a defense win", "不能自行补 allow，也不能把错误计为防御成功")], "gray", body_size=24, line_step=36)
    f.card(918, 793, 840, 229, t("Finite collaboration, not permission expansion", "有限协作，不扩张权限"), [
        t("Format / planning / evidence / boundary feedback are distinct", "分别反馈格式、规划偏差、证据不足与边界冲突"),
        t("REPLAN is feedback only; every new call is checked again", "REPLAN 只是反馈；每次新调用都需重新检查"),
        t("Budgets: repairs, repeated denials, turns and task deadline", "修复次数、重复拒绝、轮数与任务时限均有上界"),
        t("Keep successful writes; report blocked or unmet obligations", "不重复成功写入；明确报告受阻或未完成部分")], "amber", body_size=24, line_step=36)
    f.box(42, 1064, 1716, 93, "blue")
    f.text(64, 1084, t("GUARANTEE BOUNDARY", "保证边界"), 23, "blue", True)
    f.text(64, 1120, t("Exact execution binding is program-enforced. Semantic review can still be wrong; declarations do not verify tool code.",
        "程序保证审批与实际调用一致；语义审查仍可能误判，可信声明也不等于对工具实现的形式验证。"), 23)
    f.footer(t("Evaluation: utility / attack success / score coverage / errors / controlled stops / review count & latency. Preserve all failures.",
        "评测同时报告：用户任务完成、攻击成功、评分覆盖、错误、受控终止、审查次数及延迟；保留所有失败。"))
    return f


def main():
    for lang in ("zh", "en"):
        path = PDF_OUT / f"icb_guard_current_framework_{lang}.pdf"
        with PdfPages(path, metadata={"Title": "ICB-Guard: Current Review Architecture",
             "Author": "ICB-Guard", "Subject": "Implementation-grounded framework, 2026-10-23"}) as pdf:
            architecture(lang).export(pdf)
            protocol(lang).export(pdf)
    (OUT / "layout_checks.json").write_text(json.dumps(CHECKS, ensure_ascii=False, indent=2), encoding="utf-8")
    deps = ROOT / "tmp" / "pdfs" / "render_deps"
    if deps.exists():
        sys.path.insert(0, str(deps))
        import pypdfium2 as pdfium
        for lang in ("zh", "en"):
            doc = pdfium.PdfDocument(str(PDF_OUT / f"icb_guard_current_framework_{lang}.pdf"))
            for n in range(len(doc)):
                page = doc[n]
                bitmap = page.render(scale=1.45)
                bitmap.to_pil().save(OUT / f"pdf_preview_{lang}_{n+1}.png")
                bitmap.close()
                page.close()
            doc.close()
    print(json.dumps({"output": str(OUT), "pdf": str(PDF_OUT), "layout_checks": CHECKS}, ensure_ascii=False))


if __name__ == "__main__":
    main()
