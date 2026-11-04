"""Draw five portrait, icon-led ICB-Guard module flowcharts.

The visual language follows the user's reference: vertical main flow, rounded
icon nodes, dashed system boundaries, colored decision branches and feedback
loops.  Text and connections are deterministic/editable SVG objects.
"""
from pathlib import Path
import json
import os

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output" / "figures" / "module_flows_portrait"
PDF_OUT = ROOT / "output" / "pdf"
OUT.mkdir(parents=True, exist_ok=True)
PDF_OUT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "tmp" / "pdfs" / "mplconfig"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.font_manager import FontProperties
from matplotlib.patches import (
    Arc, Circle, Ellipse, FancyArrowPatch, FancyBboxPatch, Polygon, Rectangle,
)

matplotlib.rcParams.update({"svg.fonttype": "none", "pdf.fonttype": 42,
                           "savefig.facecolor": "white"})

W, H = 1200, 1500
C = {
    "navy": "#082A59", "blue": "#1476E8", "blue2": "#2E5FB8",
    "teal": "#00A5A0", "tealdark": "#007F7B", "orange": "#FF6B00",
    "red": "#EF174C", "purple": "#6742D3", "gray": "#71839A",
    "light": "#F7FAFE", "white": "#FFFFFF", "line": "#DCE7F5",
}
CHECKS = []


class Portrait:
    def __init__(self, stem, title, subtitle, index, boundary_label):
        self.stem = stem
        self.fig = plt.figure(figsize=(12, 15), dpi=120)
        self.ax = self.fig.add_axes((0, 0, 1, 1))
        self.ax.set(xlim=(0, W), ylim=(H, 0))
        self.ax.axis("off")
        self.font = FontProperties(fname="C:/Windows/Fonts/msyh.ttc")
        self.texts = []
        self.text(W / 2, 35, title, 34, "navy", True, ha="center")
        self.text(W / 2, 85, subtitle, 19, "blue2", True, ha="center")
        self.text(1148, 28, f"{index}/5", 16, "gray", True, ha="right")
        self.boundary(28, 170, 1144, 1262, boundary_label)

    def text(self, x, y, value, size=20, tone="navy", bold=False,
             ha="left", va="top", z=9):
        artist = self.ax.text(
            x, y, value, fontsize=size * .72, color=C[tone],
            fontproperties=self.font, weight="bold" if bold else "normal",
            ha=ha, va=va, linespacing=1.35, zorder=z,
        )
        self.texts.append(artist)
        return artist

    def boundary(self, x, y, w, h, label, tone="blue"):
        patch = FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0,rounding_size=78",
            edgecolor=C[tone], facecolor="none", linewidth=2.0,
            linestyle=(0, (6, 4)), zorder=0,
        )
        self.ax.add_patch(patch)
        self.text(x + 38, y + 16, label, 14, tone, True)

    def group(self, x, y, w, h, label, tone="teal"):
        patch = FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0,rounding_size=26",
            edgecolor=C[tone], facecolor=C["white"], linewidth=2.2,
            linestyle=(0, (5, 4)), zorder=1,
        )
        self.ax.add_patch(patch)
        self.text(x + w / 2, y + 14, label, 21, tone, True, ha="center")

    def node(self, x, y, w, h, title, subtitle="", tone="blue", icon="doc",
             title_size=22, subtitle_size=15, fill="white"):
        shadow = FancyBboxPatch(
            (x + 4, y + 5), w, h, boxstyle="round,pad=0,rounding_size=14",
            edgecolor="none", facecolor="#DDE8F5", alpha=.38, zorder=1,
        )
        box = FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0,rounding_size=14",
            edgecolor=C[tone], facecolor=C[fill], linewidth=2.4, zorder=2,
        )
        self.ax.add_patch(shadow)
        self.ax.add_patch(box)
        icon_size = min(52, h - 24)
        self.icon(x + 22, y + (h - icon_size) / 2, icon_size, icon, tone)
        tx = x + 22 + icon_size + 20
        title_y = y + 18 if subtitle else y + h / 2
        self.text(tx, title_y, title, title_size, "navy" if tone in {"blue", "blue2", "teal", "purple"} else tone,
                  True, va="top" if subtitle else "center")
        if subtitle:
            self.text(tx, y + h - 17, subtitle, subtitle_size,
                      "gray" if tone not in {"orange", "red"} else tone,
                      False, va="bottom")

    def mini(self, x, y, w, h, title, tone="teal", icon="check"):
        self.node(x, y, w, h, title, "", tone, icon, title_size=17)

    def icon(self, x, y, s, kind, tone):
        col = C[tone]
        lw = 2.5
        cx, cy = x + s / 2, y + s / 2
        if kind == "user":
            self.ax.add_patch(Circle((cx, y + s * .28), s * .18, facecolor=col, edgecolor="none", zorder=5))
            self.ax.add_patch(FancyBboxPatch((x + s * .18, y + s * .54), s * .64, s * .37,
                boxstyle=f"round,pad=0,rounding_size={s*.12}", facecolor=col, edgecolor="none", zorder=5))
        elif kind in {"doc", "ledger", "review"}:
            self.ax.add_patch(Rectangle((x + s*.18, y + s*.10), s*.58, s*.76,
                                        fill=False, edgecolor=col, lw=lw, zorder=5))
            for frac in (.38, .53, .68):
                self.ax.plot((x+s*.29, x+s*.65), (y+s*frac, y+s*frac), color=col, lw=lw*.75, zorder=5)
            if kind == "review":
                self.ax.add_patch(Circle((x+s*.70, y+s*.70), s*.18, fill=False, edgecolor=col, lw=lw, zorder=6))
                self.ax.plot((x+s*.82, x+s*.95), (y+s*.82, y+s*.95), color=col, lw=lw, zorder=6)
        elif kind == "shield":
            pts = [(cx, y+s*.08), (x+s*.83, y+s*.20), (x+s*.76, y+s*.64),
                   (cx, y+s*.92), (x+s*.24, y+s*.64), (x+s*.17, y+s*.20)]
            self.ax.add_patch(Polygon(pts, closed=True, facecolor=col, edgecolor=col, lw=1.5, zorder=5))
            self.ax.plot((cx, cx), (y+s*.22, y+s*.70), color="white", lw=2.0, zorder=6)
        elif kind == "lock":
            self.ax.add_patch(Arc((cx, y+s*.42), s*.48, s*.50, theta1=180, theta2=360,
                                  edgecolor=col, lw=lw, zorder=5))
            self.ax.add_patch(FancyBboxPatch((x+s*.19, y+s*.42), s*.62, s*.45,
                boxstyle=f"round,pad=0,rounding_size={s*.06}", facecolor=col, edgecolor=col, zorder=5))
            self.ax.add_patch(Circle((cx, y+s*.62), s*.055, facecolor="white", edgecolor="none", zorder=6))
            self.ax.plot((cx, cx), (y+s*.65, y+s*.75), color="white", lw=2, zorder=6)
        elif kind == "database":
            self.ax.add_patch(Ellipse((cx, y+s*.23), s*.68, s*.25, fill=False, edgecolor=col, lw=lw, zorder=5))
            self.ax.plot((x+s*.16, x+s*.16), (y+s*.23, y+s*.78), color=col, lw=lw, zorder=5)
            self.ax.plot((x+s*.84, x+s*.84), (y+s*.23, y+s*.78), color=col, lw=lw, zorder=5)
            for frac in (.50, .77):
                self.ax.add_patch(Arc((cx, y+s*frac), s*.68, s*.25, theta1=0, theta2=180,
                                      edgecolor=col, lw=lw, zorder=5))
        elif kind == "eye":
            self.ax.add_patch(Ellipse((cx, cy), s*.86, s*.52, fill=False, edgecolor=col, lw=lw, zorder=5))
            self.ax.add_patch(Circle((cx, cy), s*.16, facecolor=col, edgecolor="none", zorder=5))
            self.ax.add_patch(Circle((cx+s*.05, cy-s*.05), s*.045, facecolor="white", edgecolor="none", zorder=6))
        elif kind == "flow":
            pts = [(x+s*.22, cy), (x+s*.76, y+s*.24), (x+s*.76, y+s*.76)]
            for a, b in ((pts[0], pts[1]), (pts[0], pts[2])):
                self.ax.plot((a[0], b[0]), (a[1], b[1]), color=col, lw=lw, zorder=5)
            for px, py in pts:
                self.ax.add_patch(Circle((px, py), s*.10, facecolor=col, edgecolor="white", lw=1.4, zorder=6))
        elif kind == "check":
            self.ax.add_patch(Circle((cx, cy), s*.40, facecolor=col, edgecolor="none", zorder=5))
            self.ax.plot((x+s*.29, x+s*.45, x+s*.72), (y+s*.52, y+s*.68, y+s*.35),
                         color="white", lw=lw, solid_capstyle="round", zorder=6)
        elif kind == "stop":
            self.ax.add_patch(Circle((cx, cy), s*.39, fill=False, edgecolor=col, lw=lw, zorder=5))
            self.ax.plot((x+s*.25, x+s*.75), (y+s*.25, y+s*.75), color=col, lw=lw, zorder=6)
        elif kind == "ticket":
            self.ax.add_patch(FancyBboxPatch((x+s*.10, y+s*.24), s*.80, s*.52,
                boxstyle=f"round,pad=0,rounding_size={s*.07}", fill=False, edgecolor=col, lw=lw, zorder=5))
            self.ax.plot((cx, cx), (y+s*.29, y+s*.71), color=col, lw=lw*.75, ls=(0,(2,2)), zorder=5)
        elif kind == "clock":
            self.ax.add_patch(Circle((cx, cy), s*.38, fill=False, edgecolor=col, lw=lw, zorder=5))
            self.ax.plot((cx, cx, x+s*.70), (cy, y+s*.27, y+s*.60), color=col, lw=lw, zorder=6)
        elif kind == "wrench":
            self.ax.plot((x+s*.28, x+s*.76), (y+s*.76, y+s*.28), color=col, lw=lw*2.2,
                         solid_capstyle="round", zorder=5)
            self.ax.add_patch(Circle((x+s*.25, y+s*.79), s*.12, fill=False, edgecolor=col, lw=lw, zorder=5))
            self.ax.add_patch(Arc((x+s*.78, y+s*.25), s*.32, s*.32, theta1=30, theta2=260,
                                  edgecolor=col, lw=lw, zorder=5))
        elif kind == "brain":
            for px, py in ((.34,.35),(.55,.26),(.70,.45),(.38,.64),(.62,.70)):
                self.ax.add_patch(Circle((x+s*px, y+s*py), s*.13, fill=False, edgecolor=col, lw=lw, zorder=5))
            self.ax.plot((x+s*.36, x+s*.62), (y+s*.46, y+s*.62), color=col, lw=lw, zorder=5)
        elif kind == "anchor":
            self.ax.add_patch(Circle((cx, y+s*.20), s*.09, fill=False, edgecolor=col, lw=lw, zorder=5))
            self.ax.plot((cx, cx), (y+s*.29, y+s*.72), color=col, lw=lw, zorder=5)
            self.ax.add_patch(Arc((cx, y+s*.58), s*.70, s*.56, theta1=15, theta2=165,
                                  edgecolor=col, lw=lw, zorder=5))
        else:
            self.ax.add_patch(Circle((cx, cy), s*.36, facecolor=col, edgecolor="none", zorder=5))

    def arrow(self, points, tone="blue", dashed=False, width=2.2):
        for a, b in zip(points[:-2], points[1:-1]):
            self.ax.plot((a[0], b[0]), (a[1], b[1]), color=C[tone], lw=width,
                         linestyle=(0, (5, 4)) if dashed else "solid", zorder=3)
        a, b = points[-2:]
        self.ax.add_patch(FancyArrowPatch(
            a, b, arrowstyle="-|>", mutation_scale=16, color=C[tone], lw=width,
            linestyle=(0, (5, 4)) if dashed else "solid", shrinkA=0, shrinkB=0, zorder=4,
        ))

    def label(self, x, y, value, tone="blue", size=16, ha="center"):
        self.text(x, y, value, size, tone, True, ha=ha, va="center")

    def footer(self, value):
        self.text(W/2, 1450, value, 16, "gray", True, ha="center", va="center")

    def export(self, pdf):
        self.fig.canvas.draw()
        renderer = self.fig.canvas.get_renderer()
        inv = self.ax.transData.inverted()
        overflow = []
        for artist in self.texts:
            bb = artist.get_window_extent(renderer).transformed(inv)
            if bb.x0 < 0 or bb.x1 > W or min(bb.y0, bb.y1) < 0 or max(bb.y0, bb.y1) > H:
                overflow.append(artist.get_text())
        CHECKS.append({"figure": self.stem, "text_count": len(self.texts), "overflow": overflow})
        if overflow:
            raise ValueError(f"Text overflow in {self.stem}: {overflow}")
        stem = OUT / self.stem
        self.fig.savefig(stem.with_suffix(".svg"), format="svg")
        self.fig.savefig(stem.with_suffix(".png"), dpi=180)
        pdf.savefig(self.fig)
        plt.close(self.fig)


def hard_source():
    f = Portrait("01_hard_constraints_and_source_checks_portrait",
                 "ICB-Guard：硬约束与来源检验", "从候选调用到确定性边界检查", 1,
                 "TRUSTED HOST · 硬约束检查域")
    f.node(390, 120, 420, 86, "候选工具调用", "工具名 + 模型参数", "blue", "brain")
    f.arrow([(600, 206), (600, 248)])
    f.node(365, 248, 470, 92, "完整参数规范化", "Schema · 类型 · 默认值 · 别名", "blue", "doc")
    f.arrow([(600, 340), (600, 380)])
    f.node(365, 380, 470, 92, "资源与目的地解析", "RID / 原生 ID · 账户 · 版本 · TTL", "blue", "flow")
    f.arrow([(600, 472), (600, 522)])
    f.group(275, 522, 650, 570, "硬约束与来源检验")
    nodes = [
        (570, "工具身份与能力", "固定 Schema · 角色 · 能力证书 · 作用域", "shield"),
        (690, "业务与资源边界", "路径 / 金额 / 账户限制 · 业务禁令", "lock"),
        (810, "数据流与污染限制", "来源 · 收件人 · 披露对象 · taint", "flow"),
        (930, "来源证明与新鲜度", "实体 / 字段 / 账户 / 状态匹配", "database"),
    ]
    for y, title, sub, icon in nodes:
        f.node(330, y, 540, 88, title, sub, "teal", icon, 20, 14)
    for y in (658, 778, 898):
        f.arrow([(600, y), (600, y + 32)], "teal")
    f.arrow([(600, 1018), (600, 1135)])
    f.node(395, 1135, 410, 90, "检查结果", "PASS 只表示边界与来源成立", "blue", "review")
    f.arrow([(395, 1180), (210, 1180), (210, 1260)], "red")
    f.arrow([(600, 1225), (600, 1260)], "orange")
    f.arrow([(805, 1180), (990, 1180), (990, 1260)], "teal")
    f.mini(75, 1260, 270, 80, "硬冲突：阻断", "red", "stop")
    f.mini(465, 1260, 270, 80, "缺证据：补证", "orange", "wrench")
    f.mini(855, 1260, 270, 80, "PASS：语义审查", "teal", "check")
    f.label(600, 1118, "PASS ≠ 已获任务授权", "orange")
    f.footer("来源证明只说明参数从哪里来；不存在硬检查通过后直接执行的旁路。")
    return f


def semantic_review():
    f = Portrait("02_independent_semantic_review_portrait",
                 "ICB-Guard：独立语义审查", "逐次判断具体动作是否符合原始用户授权", 2,
                 "INDEPENDENT REVIEW · 分离上下文")
    f.node(80, 205, 300, 88, "原始请求锚点", "不可被工具输出改写", "blue", "anchor", 19, 13)
    f.node(450, 205, 300, 88, "规范化语义动作", "操作 · 目标 · 完整参数", "teal", "doc", 19, 13)
    f.node(820, 205, 300, 88, "宿主证据与历史", "EID · 来源 · 执行回执", "purple", "ledger", 19, 13)
    for x in (230, 600, 970):
        f.arrow([(x, 293), (x, 340), (600, 340), (600, 382)])
    f.node(345, 382, 510, 96, "构造本次审查包", "call_id · 状态哈希 · data-use scope", "blue", "doc")
    f.arrow([(600, 478), (600, 535)])
    f.group(270, 535, 660, 435, "独立语义审查器")
    f.node(330, 590, 540, 92, "判断任务授权", "操作 · 目标 · 范围 · 数据用途", "purple", "brain")
    f.arrow([(600, 682), (600, 724)], "purple")
    f.node(330, 724, 540, 92, "返回最小化决定", "decision · code · fields · evidence_ids", "purple", "review")
    f.arrow([(600, 816), (600, 858)], "purple")
    f.node(330, 858, 540, 88, "宿主严格校验协议", "证据引用有效；绑定哈希由宿主构造", "blue", "shield", 20, 14)
    f.arrow([(600, 970), (600, 1040)])
    f.node(400, 1040, 400, 88, "有效决定？", "无效结构最多技术纠正一次", "blue", "review")
    f.arrow([(400, 1084), (190, 1084), (190, 1185)], "red")
    f.arrow([(600, 1128), (600, 1185)], "orange")
    f.arrow([(800, 1084), (1010, 1084), (1010, 1185)], "teal")
    f.mini(55, 1185, 270, 78, "DENY：关闭路径", "red", "stop")
    f.mini(465, 1185, 270, 78, "NEEDS_EVIDENCE", "orange", "wrench")
    f.mini(875, 1185, 270, 78, "ALLOW + 数据用途允许", "teal", "check")
    f.node(395, 1305, 410, 78, "下一阶段：执行前绑定复核", "ALLOW 不能覆盖硬约束", "teal", "lock", 18, 13)
    f.arrow([(1010, 1263), (1010, 1280), (600, 1280), (600, 1305)], "teal")
    f.arrow([(930, 900), (1065, 900), (1065, 790)], "gray", dashed=True)
    f.node(940, 700, 200, 90, "技术错误", "失败则关闭执行", "gray", "stop", 17, 12)
    f.footer("独立上下文降低影响面，但不保证审查模型对注入免疫；语义判断仍可能出错。")
    return f


def pre_execution():
    f = Portrait("03_pre_execution_binding_revalidation_portrait",
                 "ICB-Guard：执行前绑定复核", "保证允许动作与实际副作用对象保持一致", 3,
                 "CONTROLLED EXECUTION · 绑定与复核域")
    f.node(390, 120, 420, 86, "语义审查 ALLOW", "只覆盖当前候选调用", "teal", "check")
    f.arrow([(600, 206), (600, 250)], "teal")
    f.node(350, 250, 500, 92, "构造精确执行绑定", "工具 · 完整参数 · call_id · session · epoch", "blue", "lock")
    f.arrow([(600, 342), (600, 386)])
    f.node(350, 386, 500, 92, "签发短期一次性凭据", "Schema · 证据 · 状态 · 资源快照哈希", "blue", "ticket")
    f.arrow([(600, 478), (600, 525)])
    f.group(260, 525, 680, 570, "执行前重新取得当前状态")
    checks = [
        (575, "动作绑定复核", "工具、参数、调用 ID 未变化", "doc"),
        (695, "资源绑定复核", "身份、账户、版本、内容状态一致", "database"),
        (815, "安全边界复核", "能力、业务、数据流、证据仍有效", "shield"),
        (935, "执行通道复核", "受信宿主与已审核工具适配器", "lock"),
    ]
    for y, title, sub, icon in checks:
        f.node(320, y, 560, 88, title, sub, "teal", icon, 20, 14)
    for y in (663, 783, 903):
        f.arrow([(600, y), (600, y + 32)], "teal")
    f.arrow([(600, 1023), (600, 1140)])
    f.node(390, 1140, 420, 88, "绑定仍有效？", "过期、重放或状态变化均拒绝", "blue", "review")
    f.arrow([(390, 1184), (175, 1184), (175, 1260)], "red")
    f.arrow([(810, 1184), (1025, 1184), (1025, 1260)], "teal")
    f.mini(55, 1260, 300, 80, "失效：重新授权", "red", "stop")
    f.mini(865, 1260, 300, 80, "有效：消费凭据", "teal", "ticket")
    f.node(450, 1260, 300, 80, "宿主执行确切动作", "同一参数 / 资源句柄", "blue", "wrench", 17, 12)
    f.arrow([(865, 1300), (750, 1300)], "teal")
    f.arrow([(600, 1340), (600, 1370)], "teal")
    f.node(420, 1370, 360, 62, "记录前后状态与结果", "成功或失败均不可重放", "purple", "ledger", 16, 11)
    f.footer("这是至多一次执行尝试，不等于远程业务事务的 exactly-once 成功或崩溃原子性。")
    return f


def bounded_feedback():
    f = Portrait("04_bounded_corrective_feedback_portrait",
                 "ICB-Guard：受限纠偏反馈", "拒绝后帮助合法任务恢复，同时不扩大权限", 4,
                 "BOUNDED RECOVERY · 反馈与重规划")
    f.node(390, 120, 420, 86, "调用未执行", "deny / needs_evidence / 技术错误", "blue", "stop")
    f.arrow([(600, 206), (600, 250)])
    f.node(390, 250, 420, 88, "分类失败原因", "硬边界 · 规划偏差 · 证据 · 协议", "blue", "review")
    f.group(220, 390, 760, 545, "固定模板反馈：只给原因与修复边界")
    f.node(270, 445, 300, 100, "硬边界 / 缺少授权", "停止动作；必要时可信确认", "red", "shield", 18, 13)
    f.node(630, 445, 300, 100, "规划偏差 / 目标错误", "指出原因码与相关字段", "orange", "review", 18, 13)
    f.node(270, 600, 300, 100, "证据不足 / 资源未定", "列出证据类别与观察引用", "orange", "database", 18, 13)
    f.node(630, 600, 300, 100, "审查协议技术错误", "格式错误或截断最多纠正一次", "gray", "doc", 18, 13)
    f.node(330, 770, 540, 95, "反馈不增加权限", "不生成替代参数，不把控制器反馈当用户指令", "teal", "lock")
    f.arrow([(600, 338), (600, 390)], "blue")
    f.arrow([(600, 865), (600, 965)], "orange")
    f.node(350, 965, 500, 92, "行动模型受限重规划", "修正参数、补充必要证据或继续独立步骤", "orange", "brain")
    f.arrow([(600, 1057), (600, 1100)])
    f.node(350, 1100, 500, 92, "预算与重复检查", "每类修复、总拒绝、轮数与时间均有上限", "red", "clock")
    f.arrow([(600, 1192), (600, 1235)])
    f.node(385, 1235, 430, 88, "产生新依据且仍在预算？", "相同拒绝不能靠换工具重置", "blue", "review", 19, 13)
    f.arrow([(385, 1279), (180, 1279), (180, 1355)], "red")
    f.arrow([(815, 1279), (1020, 1279), (1020, 1355)], "teal")
    f.mini(55, 1355, 300, 70, "否：停止 / 可信确认", "red", "stop")
    f.mini(865, 1355, 300, 70, "是：重新走完整授权链", "teal", "check")
    f.arrow([(1020, 1355), (1120, 1355), (1120, 1010), (850, 1010)], "orange")
    f.label(1080, 1080, "新调用重新审查", "orange", 15)
    f.footer("硬性阻断不会因重规划而放宽；补证查询和修正后的调用也必须重新审核。")
    return f


def trusted_records():
    f = Portrait("05_trusted_constraints_and_host_records_portrait",
                 "ICB-Guard：可信约束与宿主记录", "为检查、审查和执行提供完整性受保护的依据", 5,
                 "TRUSTED HOST · 约束与记录层")
    f.node(65, 205, 250, 82, "原始用户请求", "可信入口锚定", "blue", "user", 17, 12)
    f.node(350, 205, 250, 82, "管理员约束", "能力 / 规则 / 合同", "blue", "shield", 17, 12)
    f.node(635, 205, 250, 82, "可信确认", "独立审批身份", "blue", "check", 17, 12)
    f.node(920, 205, 215, 82, "宿主状态", "时钟 / session / 资源", "blue", "clock", 16, 11)
    for x in (190, 475, 760, 1028):
        f.arrow([(x, 287), (x, 340), (600, 340), (600, 390)])
    f.node(350, 390, 500, 90, "认证、固定版本并建立快照", "不接受行动模型自报的权限、身份或状态", "blue", "lock")
    f.arrow([(600, 480), (600, 530)])
    f.group(245, 530, 710, 575, "宿主管理的可信记录层")
    records = [
        (585, "任务与配置快照", "原始请求哈希 · 工具合同 · 策略版本", "anchor", "blue"),
        (705, "资源来源台账", "RID · 账户 · 实体版本 · 字段绑定", "database", "teal"),
        (825, "审查证据图", "EID · 类型化事实 · 有限推导 · 数据用途", "review", "purple"),
        (945, "决策与执行回执", "允许 / 拒绝 · 前后状态 · 实际结果", "ledger", "teal"),
    ]
    for y, title, sub, icon, tone in records:
        f.node(305, y, 590, 88, title, sub, tone, icon, 20, 14)
    for y in (673, 793, 913):
        f.arrow([(600, y), (600, y + 32)], "teal")
    f.node(45, 680, 230, 110, "外部工具返回", "内容仍不可信\n宿主只登记来源与哈希", "purple", "eye", 17, 12)
    f.arrow([(275, 735), (305, 735)], "purple")
    f.label(160, 650, "可能包含注入", "purple", 14)
    f.arrow([(600, 1033), (600, 1145)])
    f.node(375, 1145, 450, 88, "发布受限引用", "RID 是身份引用；EID 是证据引用", "blue", "ticket")
    f.arrow([(375, 1189), (190, 1189), (190, 1280)], "blue")
    f.arrow([(600, 1233), (600, 1280)], "purple")
    f.arrow([(825, 1189), (1010, 1189), (1010, 1280)], "teal")
    f.mini(60, 1280, 260, 78, "供硬约束检验", "blue", "shield")
    f.mini(470, 1280, 260, 78, "供语义审查", "purple", "review")
    f.mini(880, 1280, 260, 78, "供执行前复核", "teal", "lock")
    f.arrow([(1010, 1358), (1010, 1395), (905, 1395), (905, 1033)], "teal", dashed=True)
    f.label(1075, 1395, "执行后更新回执", "teal", 14)
    f.footer("记录来源可信 ≠ 外部内容真实 ≠ 数据用途获授权；三者必须分别判断。")
    return f


def main():
    figures = [hard_source(), semantic_review(), pre_execution(), bounded_feedback(), trusted_records()]
    combined = PDF_OUT / "icb_guard_five_module_flows_portrait_zh.pdf"
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
