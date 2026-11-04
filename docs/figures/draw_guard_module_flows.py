"""Draw five detailed ICB-Guard module flowcharts.

The figures describe the implemented guarded/review path and its bounded
recovery/host-record support.  They do not call any model or benchmark.
"""
from pathlib import Path
import json
import os

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output" / "figures" / "module_flows"
PDF_OUT = ROOT / "output" / "pdf"
OUT.mkdir(parents=True, exist_ok=True)
PDF_OUT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "tmp" / "pdfs" / "mplconfig"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.font_manager import FontProperties
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon, Circle

matplotlib.rcParams.update({
    "svg.fonttype": "none",
    "pdf.fonttype": 42,
    "savefig.facecolor": "white",
})

W, H = 1800, 1200
C = {
    "ink": "#17324A", "muted": "#607181", "blue": "#28679A",
    "bluebg": "#EFF6FC", "teal": "#168477", "tealbg": "#EDFAF7",
    "amber": "#C07516", "amberbg": "#FFF7E8", "red": "#BA4450",
    "redbg": "#FFF0F2", "purple": "#6F57A7", "purplebg": "#F5F1FC",
    "gray": "#8796A5", "graybg": "#F5F7F9", "white": "#FFFFFF",
}
CHECKS = []


class Flow:
    def __init__(self, stem, title, subtitle, index):
        self.stem = stem
        self.fig = plt.figure(figsize=(18, 12), dpi=120)
        self.ax = self.fig.add_axes((0, 0, 1, 1))
        self.ax.set(xlim=(0, W), ylim=(H, 0))
        self.ax.axis("off")
        self.font = FontProperties(fname="C:/Windows/Fonts/msyh.ttc")
        self.texts = []
        self.text(54, 34, "ICB-GUARD", 20, "blue", True)
        self.text(1746, 34, f"MODULE {index}/5", 18, "muted", True, ha="right")
        self.text(54, 77, title, 35, "ink", True)
        self.text(54, 132, subtitle, 20, "muted")

    def text(self, x, y, value, size=20, tone="ink", bold=False,
             ha="left", va="top", z=8):
        artist = self.ax.text(
            x, y, value, fontsize=size * .72, color=C[tone],
            fontproperties=self.font, weight="bold" if bold else "normal",
            ha=ha, va=va, linespacing=1.45, zorder=z,
        )
        self.texts.append(artist)
        return artist

    def box(self, x, y, w, h, tone="blue", dashed=False, fill=True, lw=1.6,
            radius=12):
        patch = FancyBboxPatch(
            (x, y), w, h, boxstyle=f"round,pad=0,rounding_size={radius}",
            edgecolor=C[tone], facecolor=C[tone + "bg"] if fill else C["white"],
            linewidth=lw, linestyle=(0, (6, 4)) if dashed else "solid", zorder=1,
        )
        self.ax.add_patch(patch)
        return patch

    def card(self, x, y, w, h, title, lines=(), tone="blue", badge=None,
             title_size=24, body_size=19, line_gap=35, dashed=False):
        self.box(x, y, w, h, tone, dashed=dashed)
        tx = x + 24
        if badge is not None:
            self.ax.add_patch(Circle((x + 33, y + 32), 18, facecolor=C[tone],
                                     edgecolor="none", zorder=4))
            self.text(x + 33, y + 32, str(badge), 17, "white", True,
                      ha="center", va="center")
            tx = x + 65
        self.text(tx, y + 20, title, title_size, tone, True)
        yy = y + 64
        for line in lines:
            artist = self.text(x + 24, yy, line, body_size)
            artist._bounds = (x + 15, y + 10, x + w - 15, y + h - 8)
            yy += line_gap * (line.count("\n") + 1)

    def group(self, x, y, w, h, title, tone="blue"):
        self.box(x, y, w, h, tone, dashed=True, fill=False, lw=1.5)
        self.text(x + 18, y + 14, title, 19, tone, True)

    def diamond(self, cx, cy, w, h, label, tone="blue", size=20):
        points = [(cx, cy - h / 2), (cx + w / 2, cy),
                  (cx, cy + h / 2), (cx - w / 2, cy)]
        self.ax.add_patch(Polygon(points, closed=True, edgecolor=C[tone],
                                  facecolor=C[tone + "bg"], lw=1.7, zorder=2))
        self.text(cx, cy, label, size, tone, True, ha="center", va="center")

    def arrow(self, points, tone="blue", dashed=False, width=1.8):
        if len(points) < 2:
            return
        for a, b in zip(points[:-2], points[1:-1]):
            self.ax.plot((a[0], b[0]), (a[1], b[1]), color=C[tone], lw=width,
                         linestyle=(0, (5, 4)) if dashed else "solid", zorder=3)
        a, b = points[-2], points[-1]
        self.ax.add_patch(FancyArrowPatch(
            a, b, arrowstyle="-|>", mutation_scale=14, color=C[tone],
            linewidth=width, linestyle=(0, (5, 4)) if dashed else "solid",
            shrinkA=0, shrinkB=0, zorder=4,
        ))

    def edge_label(self, x, y, value, tone="muted", size=17, ha="center"):
        self.text(x, y, value, size, tone, True, ha=ha, va="center")

    def note(self, x, y, w, text, tone="gray"):
        self.box(x, y, w, 58, tone, fill=True, lw=1.1, radius=8)
        self.text(x + 18, y + 29, text, 18, tone, True, va="center")

    def footer(self, text):
        self.ax.plot((54, 1746), (1138, 1138), color=C["gray"], lw=.8)
        self.text(54, 1157, text, 18, "muted")

    def export(self, pdf):
        self.fig.canvas.draw()
        renderer = self.fig.canvas.get_renderer()
        inverse = self.ax.transData.inverted()
        overflow = []
        overflow_details = []
        for artist in self.texts:
            bb = artist.get_window_extent(renderer).transformed(inverse)
            if bb.x0 < 0 or bb.x1 > W or min(bb.y0, bb.y1) < 0 or max(bb.y0, bb.y1) > H:
                overflow.append(artist.get_text())
            if hasattr(artist, "_bounds"):
                x0, y0, x1, y1 = artist._bounds
                if bb.x0 < x0 or bb.x1 > x1 or min(bb.y0, bb.y1) < y0 or max(bb.y0, bb.y1) > y1:
                    overflow.append(artist.get_text())
                    overflow_details.append({"text": artist.get_text(), "bbox": [bb.x0, bb.y0, bb.x1, bb.y1], "bounds": list(artist._bounds)})
        CHECKS.append({"figure": self.stem, "text_count": len(self.texts),
                       "overflow": overflow})
        if overflow:
            raise ValueError(f"Text overflow in {self.stem}: {overflow_details or overflow}")
        path = OUT / self.stem
        self.fig.savefig(path.with_suffix(".svg"), format="svg")
        self.fig.savefig(path.with_suffix(".png"), dpi=180)
        pdf.savefig(self.fig)
        plt.close(self.fig)


def hard_source():
    f = Flow(
        "01_hard_constraints_and_source_checks",
        "硬约束与来源检验",
        "先确定调用的结构、能力与参数依据是否成立；通过检查仍不代表获得任务授权。",
        1,
    )
    f.card(54, 190, 310, 112, "候选工具调用", ["工具名 + 模型给出的参数"], "gray", badge="A")
    f.card(415, 190, 430, 112, "规范化完整参数", ["Schema、类型、必填项、默认值、别名"], "blue", badge=1)
    f.card(895, 190, 420, 112, "解析资源与目的地", ["RID / 原生 ID / 账户 / 版本 / TTL"], "blue", badge=2)
    f.card(1365, 190, 380, 112, "建立来源证明", ["用户原文、宿主观察、有限确定性推导"], "teal", badge=3)
    for a, b in [((364, 246), (415, 246)), ((845, 246), (895, 246)), ((1315, 246), (1365, 246))]:
        f.arrow([a, b])

    f.group(54, 358, 1691, 328, "宿主独立执行的确定性检查")
    checks = [
        (80, "工具与能力", ["工具身份及固定 Schema", "角色、能力证书、作用域"]),
        (490, "业务与资源边界", ["账户 / 路径 / 金额等限制", "独立业务禁令与副作用上界"]),
        (900, "数据流与污染状态", ["来源、收件人、披露对象", "taint 与跨工具数据使用限制"]),
        (1310, "参数来源与新鲜度", ["实体、字段、账户和状态匹配", "歧义、过期、跨任务均无效"]),
    ]
    for i, (x, title, lines) in enumerate(checks, 1):
        f.card(x, 410, 355, 220, title, lines, "blue" if i < 4 else "teal",
               badge=i, body_size=18, line_gap=38)
        if i < 4:
            f.arrow([(x + 355, 520), (x + 410, 520)])
    f.arrow([(1555, 630), (1555, 748)])
    f.diamond(1555, 820, 310, 142, "检查结果？", "blue", 22)

    f.card(1090, 936, 405, 125, "PASS：进入语义审查", ["只证明边界与来源条件满足"], "teal")
    f.card(590, 936, 420, 125, "证据不足 / 目标歧义", ["返回补证要求；不自动补参数"], "amber")
    f.card(90, 936, 420, 125, "硬约束冲突", ["阻断调用；必要时请求可信确认"], "red")
    f.arrow([(1480, 864), (1290, 936)], "teal")
    f.edge_label(1372, 906, "全部通过", "teal")
    f.arrow([(1455, 820), (800, 820), (800, 936)], "amber")
    f.edge_label(1058, 800, "缺少可验证来源", "amber")
    f.arrow([(1400, 800), (300, 800), (300, 936)], "red")
    f.edge_label(560, 780, "能力 / 业务 / 数据流不满足", "red")
    f.note(54, 1081, 1691, "关键边界：来源证明只说明参数从哪里来；它不证明用户允许以该方式使用参数。", "purple")
    f.footer("输出只有三类：继续审查、补充证据或阻断；不存在“硬检查 PASS 后直接执行”的旁路。")
    return f


def semantic_review():
    f = Flow(
        "02_independent_semantic_review",
        "独立语义审查",
        "在与行动模型分离的上下文中，判断这一次具体动作是否得到原始用户请求授权。",
        2,
    )
    f.card(54, 190, 470, 150, "不可变任务锚点", ["原始用户请求、可信时间与明确条件", "工具输出不能改写该授权根"], "blue", badge="I")
    f.card(665, 190, 470, 150, "规范化语义动作", ["操作、资源、目的地、完整参数", "数据来源及声明的副作用上界"], "teal", badge="A")
    f.card(1276, 190, 469, 150, "宿主证据与历史", ["观察 EID、来源摘要、执行回执", "工具正文仍按不可信数据处理"], "purple", badge="E")
    for x in (289, 900, 1510):
        f.arrow([(x, 340), (x, 398), (900, 398), (900, 445)])

    f.card(585, 445, 630, 145, "构造本次审查包", ["绑定 call_id、完整参数、状态哈希与 data-use scope", "模型只需返回最小化判断字段"], "blue", badge=1)
    f.arrow([(900, 590), (900, 642)])
    f.card(585, 642, 630, 142, "独立审查器判断", ["用户是否授权该操作、目标、范围与数据用途", "输出 decision / code / fields / evidence_ids"], "purple", badge=2)
    f.arrow([(1215, 713), (1295, 713)])
    f.card(1295, 642, 450, 142, "宿主严格校验协议", ["字段、原因码和证据引用必须有效", "哈希与内部绑定由宿主构造"], "blue", badge=3)
    f.arrow([(1520, 784), (1520, 838)])
    f.diamond(1520, 905, 320, 130, "有效决定？", "blue", 21)

    f.card(1060, 1002, 410, 108, "ALLOW 且数据使用允许", ["转入执行前绑定复核"], "teal")
    f.card(570, 1002, 410, 108, "NEEDS_EVIDENCE", ["指出缺失事实，进入受限补证"], "amber")
    f.card(80, 1002, 410, 108, "DENY", ["拒绝该动作并关闭相应语义路径"], "red")
    f.arrow([(1450, 952), (1265, 1002)], "teal")
    f.arrow([(1425, 930), (775, 930), (775, 1002)], "amber")
    f.arrow([(1390, 905), (285, 905), (285, 1002)], "red")

    f.card(54, 642, 440, 142, "技术性无效输出", ["结构错误 / 截断：最多纠正一次", "仍失败则关闭执行并记未评分错误"], "gray", badge="!")
    f.arrow([(1295, 675), (1245, 675), (1245, 615), (274, 615), (274, 642)], "gray", dashed=True)
    f.note(54, 808, 1110, "审查器可能误判：上下文独立降低影响面，但不等于模型对注入免疫。", "purple")
    f.footer("ALLOW 是一次调用的语义判断；它不能清除污染状态、覆盖硬性规则或自行触发执行。")
    return f


def pre_execution():
    f = Flow(
        "03_pre_execution_binding_revalidation",
        "执行前绑定复核",
        "把审批绑定到确切动作和状态，并在实际副作用发生前再次确认所有条件仍然成立。",
        3,
    )
    f.card(54, 190, 350, 118, "语义审查 ALLOW", ["只覆盖当前候选调用"], "teal", badge="A")
    f.card(455, 190, 585, 124, "构造精确执行绑定", ["工具 / 完整参数 / call_id / session / epoch", "Schema、证据、上下文及资源快照哈希"], "blue", badge=1, body_size=14, line_gap=25)
    f.card(1090, 190, 655, 124, "签发短期一次性执行凭据", ["不可跨动作、跨资源、跨状态或重复使用", "模拟宿主：在同一锁内保持状态绑定"], "blue", badge=2, body_size=14, line_gap=25)
    f.arrow([(404, 249), (455, 249)], "teal")
    f.arrow([(1040, 249), (1090, 249)])

    f.group(54, 370, 1691, 296, "执行前重新取得当前状态并复核")
    items = [
        (80, "动作绑定", ["工具、参数、调用 ID 未变化", "票据未过期、未消费、未撤销"]),
        (495, "资源绑定", ["身份 / 账户 / 版本 / 内容状态一致", "新建目标仍不存在，父目录身份一致"]),
        (910, "安全边界", ["能力、业务、数据流与污染状态", "证据和授权上下文仍然有效"]),
        (1325, "执行通道", ["受信宿主及已审核工具适配器", "不回退到任意客户端回调"]),
    ]
    for i, (x, title, lines) in enumerate(items, 1):
        f.card(x, 420, 340, 202, title, lines, "blue" if i != 2 else "teal",
               badge=i, body_size=17, line_gap=36)
        if i < 4:
            f.arrow([(x + 340, 521), (x + 415, 521)])

    f.arrow([(1495, 622), (1495, 720)])
    f.diamond(1495, 795, 330, 140, "绑定仍有效？", "blue", 22)
    f.card(1080, 915, 400, 125, "消费凭据并开始尝试", ["成功与失败均不能重放"], "teal")
    f.card(615, 915, 385, 125, "宿主执行确切动作", ["使用同一规范化参数 / 资源句柄"], "teal")
    f.card(150, 915, 385, 125, "记录真实执行结果", ["前后状态哈希、调用 ID、成功或失败"], "purple")
    f.arrow([(1420, 858), (1280, 915)], "teal")
    f.arrow([(1080, 977), (1000, 977)], "teal")
    f.arrow([(615, 977), (535, 977)], "teal")

    f.card(54, 700, 570, 138, "状态变化 / 过期 / 重放 / 绑定不一致", ["关闭执行并使原允许结果失效", "需要基于新状态重新授权；不得静默重试"], "red", badge="X", body_size=18)
    f.arrow([(1330, 795), (624, 795)], "red")
    f.edge_label(930, 775, "任一条件不再成立", "red")
    f.note(54, 1068, 1691, "保证边界：这是“至多一次执行尝试”，不等于远程业务事务的 exactly-once 成功或崩溃原子性。", "gray")
    f.footer("允许动作与实际执行对象必须保持一致；路径字符串相同但资源身份或内容状态改变时仍应拒绝。")
    return f


def bounded_feedback():
    f = Flow(
        "04_bounded_corrective_feedback",
        "受限纠偏反馈",
        "把拒绝原因转化为可操作但不授予新权限的反馈，使合法任务可以在原始范围内继续。",
        4,
    )
    f.card(54, 190, 360, 122, "调用未执行", ["拒绝 / 补证 / 技术错误"], "gray", badge="R")
    f.arrow([(414, 251), (510, 251)])
    f.diamond(690, 251, 360, 150, "失败类别？", "blue", 22)

    columns = [54, 480, 906, 1332]
    titles = ["硬边界或缺少授权", "规划偏差 / 目标错误", "证据不足 / 资源未定", "审查协议技术错误"]
    tones = ["red", "amber", "amber", "gray"]
    bodies = [
        ["能力、业务或数据流边界冲突", "停止该动作；必要时请求可信确认"],
        ["固定模板指出原因码与相关字段", "关闭重复语义路径，允许独立步骤继续"],
        ["给出所需证据类别与已有观察引用", "行动模型只能提出任务相关补证调用"],
        ["格式错误或截断最多纠正一次", "有效 deny 不得重问以争取 allow"],
    ]
    for i, (x, title, tone, lines) in enumerate(zip(columns, titles, tones, bodies), 1):
        f.card(x, 390, 372, 220, title, lines, tone, badge=i,
               title_size=21, body_size=17, line_gap=38)
    f.arrow([(690, 326), (690, 350), (240, 350), (240, 390)], "red")
    f.arrow([(690, 326), (690, 390)], "amber")
    f.arrow([(690, 350), (1092, 350), (1092, 390)], "amber")
    f.arrow([(690, 350), (1518, 350), (1518, 390)], "gray")

    f.card(480, 694, 372, 146, "行动模型受限重规划", ["修正参数、改走原任务内必要步骤", "反馈不是新的用户指令或授权"], "amber", badge=5, body_size=17)
    f.card(906, 694, 372, 146, "补证调用也重新审核", ["查询本身须通过完整授权链", "只有宿主观察变化才可重审相同调用"], "blue", badge=6, body_size=17)
    f.card(1332, 694, 372, 146, "预算与重复检查", ["默认每类最多 2 次修复、总拒绝 6 次", "同义工具不能重置已关闭语义路径"], "red", badge=7, body_size=17)
    f.arrow([(666, 610), (666, 694)], "amber")
    f.arrow([(1092, 610), (1092, 694)], "amber")
    f.arrow([(1518, 610), (1518, 694)], "gray")
    f.arrow([(852, 767), (906, 767)], "blue")
    f.arrow([(1278, 767), (1332, 767)], "blue")

    f.diamond(1110, 940, 390, 142, "仍在预算且产生新依据？", "blue", 20)
    f.arrow([(1518, 840), (1518, 940), (1305, 940)], "blue")
    f.card(560, 1012, 420, 105, "是：重新提出候选调用", ["从硬约束开始走完整授权链"], "teal")
    f.card(1260, 1012, 420, 105, "否：停止该路径", ["报告受阻或请求可信用户确认"], "red")
    f.arrow([(1010, 991), (770, 1012)], "teal")
    f.arrow([(1210, 991), (1470, 1012)], "red")
    f.note(54, 886, 600, "硬性阻断不会因重新规划而放宽。", "red")
    f.footer("恢复目标是提高合法任务完成率，同时保持原始授权边界；每一个修正后的调用都重新审查。")
    return f


def trusted_records():
    f = Flow(
        "05_trusted_constraints_and_host_records",
        "可信约束与宿主记录",
        "可信指记录的来源与完整性由受信组件维护；它不自动证明外部内容真实或用途已获授权。",
        5,
    )
    sources = [
        (54, "原始用户请求", ["可信入口认证并锚定", "不可被工具内容改写"]),
        (480, "管理员约束", ["能力、业务规则、固定 Schema", "来源 / 数据流 / 副作用合同"]),
        (906, "可信确认", ["独立审批身份", "绑定单一动作与资源状态"]),
        (1332, "宿主运行状态", ["时钟、session、epoch", "原生账户、资源身份与版本"]),
    ]
    for i, (x, title, lines) in enumerate(sources, 1):
        f.card(x, 190, 372, 162, title, lines, "blue", badge=i,
               title_size=21, body_size=17, line_gap=35)
        f.arrow([(x + 186, 352), (x + 186, 410)])

    f.group(54, 410, 1691, 382, "可信宿主管理的记录层")
    records = [
        (80, "任务与配置快照", ["原始请求哈希", "工具合同 / 策略版本"]),
        (485, "资源来源台账", ["RID、账户、实体版本", "原始结果与字段绑定"]),
        (890, "审查证据图", ["EID、类型化事实", "有限推导与数据使用范围"]),
        (1295, "决策与执行回执", ["调用 / 决定 / 拒绝", "前后状态与实际结果"]),
    ]
    for i, (x, title, lines) in enumerate(records, 1):
        f.card(x, 465, 350, 225, title, lines, "teal" if i > 1 else "blue",
               badge=i, title_size=21, body_size=18, line_gap=38)
        if i < 4:
            f.arrow([(x + 350, 578), (x + 405, 578)], "teal")

    f.card(54, 835, 430, 170, "外部工具返回", ["正文、描述和参数字符串可能含注入", "内容保持不可信；只由宿主登记来源和哈希"], "purple", badge="U", body_size=18)
    f.arrow([(269, 835), (269, 770), (485, 770)], "purple")
    f.edge_label(350, 749, "观察后登记", "purple")

    f.card(575, 835, 340, 170, "供硬约束检验", ["能力、来源、新鲜度", "账户与资源匹配"], "blue", badge="H", body_size=18)
    f.card(970, 835, 340, 170, "供语义审查", ["原始请求与 EID", "动作、用途和历史"], "purple", badge="S", body_size=18)
    f.card(1365, 835, 380, 170, "供执行前复核", ["状态、资源与票据绑定", "执行后追加真实回执"], "teal", badge="X", body_size=18)
    f.arrow([(660, 690), (745, 835)], "blue")
    f.arrow([(1065, 690), (1140, 835)], "purple")
    f.arrow([(1470, 690), (1555, 835)], "teal")
    f.arrow([(1555, 1005), (1555, 1050), (1470, 1050), (1470, 792)], "teal", dashed=True)
    f.edge_label(1640, 1050, "执行后更新", "teal")

    f.card(54, 1020, 740, 105, "失效处理", ["歧义、过期、跨账户、跨任务或哈希不匹配 → 不得作为证据使用"], "red", title_size=20, body_size=17)
    f.note(830, 1020, 915, "RID 是身份引用，EID 是证据引用；两者都不是权限凭据。", "gray")
    f.footer("记录可信 ≠ 内容真实 ≠ 用途获授权；三者分别由来源检查、语义审查和执行复核处理。")
    return f


def main():
    figures = [hard_source(), semantic_review(), pre_execution(), bounded_feedback(), trusted_records()]
    combined = PDF_OUT / "icb_guard_five_module_flows_zh.pdf"
    with PdfPages(combined) as pdf:
        for figure in figures:
            figure.export(pdf)
    (OUT / "layout_checks.json").write_text(
        json.dumps(CHECKS, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({"figures": len(figures), "output": str(OUT),
                      "pdf": str(combined), "checks": CHECKS}, ensure_ascii=False))


if __name__ == "__main__":
    main()
