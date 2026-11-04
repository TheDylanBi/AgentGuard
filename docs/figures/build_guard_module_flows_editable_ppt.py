from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".codex-pptx-build" / "vendor"))

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.dml import MSO_LINE_DASH_STYLE
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, MSO_AUTO_SIZE, PP_ALIGN
from pptx.util import Inches, Pt
from pptx.oxml.xmlchemy import OxmlElement


OUT = ROOT / "output" / "pptx" / "icb_guard_five_module_flows_editable.pptx"
FONT = "Microsoft YaHei"
SYMBOL_FONT = "Segoe UI Symbol"

C = {
    "navy": RGBColor(8, 42, 89),
    "blue": RGBColor(20, 118, 232),
    "blue2": RGBColor(46, 95, 184),
    "teal": RGBColor(0, 165, 160),
    "orange": RGBColor(255, 107, 0),
    "red": RGBColor(239, 23, 76),
    "purple": RGBColor(103, 66, 211),
    "gray": RGBColor(113, 131, 154),
    "white": RGBColor(255, 255, 255),
    "shadow": RGBColor(221, 232, 245),
}


def u(v: float):
    return Inches(v / 100.0)


def set_arrow(line_shape):
    ln = line_shape._element.spPr.get_or_add_ln()
    tail = ln.find("{http://schemas.openxmlformats.org/drawingml/2006/main}tailEnd")
    if tail is None:
        tail = OxmlElement("a:tailEnd")
        ln.append(tail)
    tail.set("type", "triangle")
    tail.set("w", "med")
    tail.set("len", "med")


def add_text(slide, x, y, w, h, text, size=18, tone="navy", bold=False,
             align=PP_ALIGN.LEFT, valign=MSO_ANCHOR.MIDDLE, font=FONT):
    box = slide.shapes.add_textbox(u(x), u(y), u(w), u(h))
    box.name = f"Text — {text[:28]}"
    tf = box.text_frame
    tf.clear()
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.NONE
    tf.vertical_anchor = valign
    lines = str(text).split("\n")
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = line
        p.alignment = align
        p.font.name = font
        p.font.size = Pt(size)
        p.font.bold = bold
        p.font.color.rgb = C[tone]
        p.space_after = Pt(0)
        p.space_before = Pt(0)
    return box


def add_round_rect(slide, x, y, w, h, tone="blue", dashed=False, fill=True,
                   weight=2.2, shadow=False):
    if shadow:
        sh = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, u(x + 4), u(y + 5), u(w), u(h))
        sh.name = "Editable soft shadow"
        sh.fill.solid(); sh.fill.fore_color.rgb = C["shadow"]
        sh.fill.transparency = 55
        sh.line.fill.background()
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, u(x), u(y), u(w), u(h))
    shape.name = "Editable rounded container"
    if fill:
        shape.fill.solid(); shape.fill.fore_color.rgb = C["white"]
    else:
        shape.fill.background()
    shape.line.color.rgb = C[tone]
    shape.line.width = Pt(weight)
    if dashed:
        shape.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    return shape


def add_line(slide, x1, y1, x2, y2, tone="blue", weight=2.2, arrow=False, dashed=False):
    line = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, u(x1), u(y1), u(x2), u(y2))
    line.name = "Editable arrow connector" if arrow else "Editable connector"
    line.line.color.rgb = C[tone]
    line.line.width = Pt(weight)
    if dashed:
        line.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    if arrow:
        set_arrow(line)
    return line


def add_arrow(slide, points, tone="blue", dashed=False, weight=2.2):
    for i, (a, b) in enumerate(zip(points, points[1:])):
        add_line(slide, a[0], a[1], b[0], b[1], tone, weight, i == len(points) - 2, dashed)


def add_icon(slide, x, y, s, kind, tone):
    col = C[tone]
    if kind == "user":
        a = slide.shapes.add_shape(MSO_SHAPE.OVAL, u(x+s*.36), u(y+s*.05), u(s*.28), u(s*.28))
        b = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, u(x+s*.20), u(y+s*.48), u(s*.60), u(s*.42))
        for q in (a, b): q.fill.solid(); q.fill.fore_color.rgb = col; q.line.fill.background()
    elif kind == "database":
        a = slide.shapes.add_shape(MSO_SHAPE.CAN, u(x+s*.14), u(y+s*.10), u(s*.72), u(s*.78))
        a.fill.background(); a.line.color.rgb = col; a.line.width = Pt(2.2)
    elif kind == "check":
        a = slide.shapes.add_shape(MSO_SHAPE.OVAL, u(x+s*.08), u(y+s*.08), u(s*.84), u(s*.84))
        a.fill.solid(); a.fill.fore_color.rgb = col; a.line.fill.background()
        add_text(slide, x+s*.17, y+s*.08, s*.67, s*.68, "✓", s*.45, "white", True, PP_ALIGN.CENTER, MSO_ANCHOR.MIDDLE, SYMBOL_FONT)
    elif kind == "stop":
        a = slide.shapes.add_shape(MSO_SHAPE.OVAL, u(x+s*.08), u(y+s*.08), u(s*.84), u(s*.84))
        a.fill.background(); a.line.color.rgb = col; a.line.width = Pt(2.5)
        add_line(slide, x+s*.22, y+s*.22, x+s*.78, y+s*.78, tone, 2.8)
    elif kind == "shield":
        a = slide.shapes.add_shape(MSO_SHAPE.PENTAGON, u(x+s*.14), u(y+s*.06), u(s*.72), u(s*.84))
        a.rotation = 180; a.fill.solid(); a.fill.fore_color.rgb = col; a.line.fill.background()
        add_text(slide, x+s*.30, y+s*.23, s*.40, s*.45, "!", s*.31, "white", True, PP_ALIGN.CENTER)
    elif kind == "lock":
        ring = slide.shapes.add_shape(MSO_SHAPE.ARC, u(x+s*.24), u(y+s*.06), u(s*.52), u(s*.58))
        ring.fill.background(); ring.line.color.rgb = col; ring.line.width = Pt(2.2)
        body = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, u(x+s*.18), u(y+s*.40), u(s*.64), u(s*.48))
        body.fill.solid(); body.fill.fore_color.rgb = col; body.line.fill.background()
        add_text(slide, x+s*.36, y+s*.40, s*.28, s*.34, "•", s*.28, "white", True, PP_ALIGN.CENTER)
    elif kind == "flow":
        add_line(slide, x+s*.27, y+s*.52, x+s*.72, y+s*.25, tone, 2.1)
        add_line(slide, x+s*.27, y+s*.52, x+s*.72, y+s*.76, tone, 2.1)
        for px, py in ((.18,.43),(.63,.16),(.63,.67)):
            o = slide.shapes.add_shape(MSO_SHAPE.OVAL, u(x+s*px), u(y+s*py), u(s*.18), u(s*.18))
            o.fill.solid(); o.fill.fore_color.rgb = col; o.line.fill.background()
    elif kind == "eye":
        a = slide.shapes.add_shape(MSO_SHAPE.OVAL, u(x+s*.08), u(y+s*.26), u(s*.84), u(s*.48))
        a.fill.background(); a.line.color.rgb = col; a.line.width = Pt(2.2)
        b = slide.shapes.add_shape(MSO_SHAPE.OVAL, u(x+s*.39), u(y+s*.39), u(s*.22), u(s*.22))
        b.fill.solid(); b.fill.fore_color.rgb = col; b.line.fill.background()
    elif kind == "clock":
        a = slide.shapes.add_shape(MSO_SHAPE.OVAL, u(x+s*.10), u(y+s*.10), u(s*.80), u(s*.80))
        a.fill.background(); a.line.color.rgb = col; a.line.width = Pt(2.2)
        add_line(slide, x+s*.50, y+s*.50, x+s*.50, y+s*.25, tone, 2.1)
        add_line(slide, x+s*.50, y+s*.50, x+s*.70, y+s*.62, tone, 2.1)
    elif kind == "ticket":
        a = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, u(x+s*.10), u(y+s*.25), u(s*.80), u(s*.50))
        a.fill.background(); a.line.color.rgb = col; a.line.width = Pt(2.2)
        add_line(slide, x+s*.50, y+s*.30, x+s*.50, y+s*.70, tone, 1.6, False, True)
    elif kind in ("wrench", "anchor"):
        add_text(slide, x, y-s*.02, s, s, "⚒" if kind == "wrench" else "⚓", s*.62, tone, True, PP_ALIGN.CENTER, MSO_ANCHOR.MIDDLE, SYMBOL_FONT)
    elif kind == "brain":
        for px, py in ((.18,.23),(.40,.12),(.60,.24),(.26,.51),(.50,.56),(.36,.76)):
            o = slide.shapes.add_shape(MSO_SHAPE.OVAL, u(x+s*px), u(y+s*py), u(s*.27), u(s*.27))
            o.fill.background(); o.line.color.rgb = col; o.line.width = Pt(2)
    else:
        r = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, u(x+s*.18), u(y+s*.08), u(s*.62), u(s*.80))
        r.fill.background(); r.line.color.rgb = col; r.line.width = Pt(2.2)
        for yy in (.38,.53,.68): add_line(slide, x+s*.29, y+s*yy, x+s*.69, y+s*yy, tone, 1.5)
        if kind == "review":
            o = slide.shapes.add_shape(MSO_SHAPE.OVAL, u(x+s*.62), u(y+s*.62), u(s*.27), u(s*.27))
            o.fill.background(); o.line.color.rgb = col; o.line.width = Pt(1.9)
            add_line(slide, x+s*.82, y+s*.82, x+s*.96, y+s*.96, tone, 1.9)


def add_node(slide, x, y, w, h, title, subtitle="", tone="blue", icon="doc", title_size=18, subtitle_size=11):
    add_round_rect(slide, x, y, w, h, tone, shadow=True)
    s = min(52, h - 24)
    add_icon(slide, x+22, y+(h-s)/2, s, icon, tone)
    tx = x + 22 + s + 18
    title_tone = tone if tone in ("red", "orange") else "navy"
    if subtitle:
        add_text(slide, tx, y+14, w-(tx-x)-18, 32, title, title_size, title_tone, True)
        sub_tone = tone if tone in ("red", "orange") else "gray"
        add_text(slide, tx, y+h-38, w-(tx-x)-18, 30, subtitle, subtitle_size, sub_tone)
    else:
        add_text(slide, tx, y, w-(tx-x)-18, h, title, title_size, title_tone, True)


def add_boundary(slide, label):
    add_round_rect(slide, 28, 170, 1144, 1262, "blue", True, False, 1.8)
    add_text(slide, 66, 184, 500, 24, label, 13, "blue", True, valign=MSO_ANCHOR.TOP)


def add_group(slide, x, y, w, h, label):
    add_round_rect(slide, x, y, w, h, "teal", True, False, 1.8)
    add_text(slide, x, y+13, w, 32, label, 17, "teal", True, PP_ALIGN.CENTER, MSO_ANCHOR.TOP)


def add_base(prs, title, subtitle, index, boundary):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    bg = slide.background.fill; bg.solid(); bg.fore_color.rgb = C["white"]
    add_text(slide, 120, 30, 960, 58, title, 29, "navy", True, PP_ALIGN.CENTER, MSO_ANCHOR.TOP)
    add_text(slide, 180, 84, 840, 38, subtitle, 16, "blue2", True, PP_ALIGN.CENTER, MSO_ANCHOR.TOP)
    add_text(slide, 1100, 25, 55, 30, f"{index}/5", 12, "gray", True, PP_ALIGN.RIGHT, MSO_ANCHOR.TOP)
    add_boundary(slide, boundary)
    return slide


def footer(slide, text):
    add_text(slide, 110, 1444, 980, 28, text, 11, "gray", True, PP_ALIGN.CENTER, MSO_ANCHOR.TOP)


def slide1(prs):
    s=add_base(prs,"ICB-Guard：硬约束与来源检验","从候选调用到确定性边界检查",1,"TRUSTED HOST · 硬约束检查域")
    add_node(s,390,120,420,86,"候选工具调用","工具名 + 模型参数","blue","brain",19,12); add_arrow(s,[(600,206),(600,248)])
    add_node(s,365,248,470,92,"完整参数规范化","Schema · 类型 · 默认值 · 别名","blue","doc",18,11); add_arrow(s,[(600,340),(600,380)])
    add_node(s,365,380,470,92,"资源与目的地解析","RID / 原生 ID · 账户 · 版本 · TTL","blue","flow",18,11); add_arrow(s,[(600,472),(600,522)])
    add_group(s,275,522,650,570,"硬约束与来源检验")
    rows=[(570,"工具身份与能力","固定 Schema · 角色 · 能力证书 · 作用域","shield"),(690,"业务与资源边界","路径 / 金额 / 账户限制 · 业务禁令","lock"),(810,"数据流与污染限制","来源 · 收件人 · 披露对象 · taint","flow"),(930,"来源证明与新鲜度","实体 / 字段 / 账户 / 状态匹配","database")]
    for y,t,sub,ic in rows: add_node(s,330,y,540,88,t,sub,"teal",ic,17,10)
    for y in (658,778,898): add_arrow(s,[(600,y),(600,y+32)],"teal")
    add_arrow(s,[(600,1018),(600,1135)]); add_node(s,395,1135,410,90,"检查结果","PASS 只表示边界与来源成立","blue","review",18,11)
    add_text(s,455,1106,290,24,"PASS ≠ 已获任务授权",13,"orange",True,PP_ALIGN.CENTER)
    add_arrow(s,[(395,1180),(210,1180),(210,1260)],"red"); add_arrow(s,[(600,1225),(600,1260)],"orange"); add_arrow(s,[(805,1180),(990,1180),(990,1260)],"teal")
    add_node(s,75,1260,270,80,"硬冲突：阻断",tone="red",icon="stop",title_size=15); add_node(s,465,1260,270,80,"缺证据：补证",tone="orange",icon="wrench",title_size=15); add_node(s,855,1260,270,80,"PASS：语义审查",tone="teal",icon="check",title_size=15)
    footer(s,"来源证明只说明参数从哪里来，不存在硬检查通过后直接执行的旁路。")


def slide2(prs):
    s=add_base(prs,"ICB-Guard：独立语义审查","逐次判断具体动作是否符合原始用户授权",2,"INDEPENDENT REVIEW · 分离上下文")
    add_node(s,80,205,300,88,"原始请求锚点","工具输出不能改写","blue","anchor",16,10); add_node(s,450,205,300,88,"规范化语义动作","操作 · 目标 · 完整参数","teal","doc",16,10); add_node(s,820,205,300,88,"宿主证据与历史","EID · 来源 · 执行回执","purple","doc",16,10)
    for x in (230,600,970): add_arrow(s,[(x,293),(x,340),(600,340),(600,382)])
    add_node(s,345,382,510,96,"构造本次审查包","call_id · 状态哈希 · data-use scope","blue","doc",18,11); add_arrow(s,[(600,478),(600,535)])
    add_group(s,270,535,660,435,"独立语义审查器"); add_node(s,330,590,540,92,"判断任务授权","操作 · 目标 · 范围 · 数据用途","purple","brain",18,11); add_arrow(s,[(600,682),(600,724)],"purple")
    add_node(s,330,724,540,92,"返回最小化决定","decision · code · fields · evidence_ids","purple","review",18,11); add_arrow(s,[(600,816),(600,858)],"purple")
    add_node(s,330,858,540,88,"宿主严格校验协议","证据引用有效，绑定哈希由宿主构造","blue","shield",17,10); add_arrow(s,[(600,970),(600,1040)])
    add_node(s,400,1040,400,88,"有效决定？","无效结构最多技术纠正一次","blue","review",18,10)
    add_arrow(s,[(400,1084),(190,1084),(190,1185)],"red"); add_arrow(s,[(600,1128),(600,1185)],"orange"); add_arrow(s,[(800,1084),(1010,1084),(1010,1185)],"teal")
    add_node(s,55,1185,270,78,"DENY：关闭路径",tone="red",icon="stop",title_size=14); add_node(s,465,1185,270,78,"NEEDS_EVIDENCE",tone="orange",icon="wrench",title_size=13); add_node(s,875,1185,270,78,"ALLOW + 数据用途允许",tone="teal",icon="check",title_size=13)
    add_node(s,395,1305,410,78,"下一阶段：执行前绑定复核","ALLOW 不能覆盖硬约束","teal","lock",15,9); add_arrow(s,[(1010,1263),(1010,1280),(600,1280),(600,1305)],"teal")
    add_node(s,940,700,200,90,"技术错误","失败则关闭执行","gray","stop",14,9); add_arrow(s,[(930,900),(1065,900),(1065,790)],"gray",True)
    footer(s,"独立上下文降低影响面，但不保证审查模型对注入免疫，语义判断仍可能出错。")


def slide3(prs):
    s=add_base(prs,"ICB-Guard：执行前绑定复核","保证允许动作与实际副作用对象保持一致",3,"CONTROLLED EXECUTION · 绑定与复核域")
    add_node(s,390,120,420,86,"语义审查 ALLOW","只覆盖当前候选调用","teal","check",18,11); add_arrow(s,[(600,206),(600,250)],"teal")
    add_node(s,350,250,500,92,"构造精确执行绑定","工具 · 完整参数 · call_id · session · epoch","blue","lock",18,10); add_arrow(s,[(600,342),(600,386)])
    add_node(s,350,386,500,92,"签发短期一次性凭据","Schema · 证据 · 状态 · 资源快照哈希","blue","ticket",18,10); add_arrow(s,[(600,478),(600,525)])
    add_group(s,260,525,680,570,"执行前重新取得当前状态")
    rows=[(575,"动作绑定复核","工具、参数、调用 ID 未变化","doc"),(695,"资源绑定复核","身份、账户、版本、内容状态一致","database"),(815,"安全边界复核","能力、业务、数据流、证据仍有效","shield"),(935,"执行通道复核","受信宿主与已审核工具适配器","lock")]
    for y,t,sub,ic in rows: add_node(s,320,y,560,88,t,sub,"teal",ic,17,10)
    for y in (663,783,903): add_arrow(s,[(600,y),(600,y+32)],"teal")
    add_arrow(s,[(600,1023),(600,1140)]); add_node(s,390,1140,420,88,"绑定仍有效？","过期、重放或状态变化均拒绝","blue","review",18,10)
    add_arrow(s,[(390,1184),(175,1184),(175,1260)],"red"); add_arrow(s,[(810,1184),(1025,1184),(1025,1260)],"teal")
    add_node(s,55,1260,300,80,"失效：重新授权",tone="red",icon="stop",title_size=15); add_node(s,865,1260,300,80,"有效：消费凭据",tone="teal",icon="ticket",title_size=15); add_node(s,450,1260,300,80,"宿主执行确切动作","同一参数 / 资源句柄","blue","wrench",14,9)
    add_arrow(s,[(865,1300),(750,1300)],"teal"); add_arrow(s,[(600,1340),(600,1370)],"teal")
    add_node(s,420,1370,360,62,"记录前后状态与结果","成功或失败均不可重放","purple","doc",13,8)
    footer(s,"这是至多一次执行尝试，不等于远程业务事务的 exactly-once 成功或崩溃原子性。")


def slide4(prs):
    s=add_base(prs,"ICB-Guard：受限纠偏反馈","拒绝后帮助合法任务恢复，同时不扩大权限",4,"BOUNDED RECOVERY · 反馈与重规划")
    add_node(s,390,120,420,86,"调用未执行","deny / needs_evidence / 技术错误","blue","stop",18,10); add_arrow(s,[(600,206),(600,250)])
    add_node(s,390,250,420,88,"分类失败原因","硬边界 · 规划偏差 · 证据 · 协议","blue","review",18,10); add_arrow(s,[(600,338),(600,390)])
    add_group(s,220,390,760,545,"固定模板反馈：只给原因与修复边界")
    add_node(s,270,445,300,100,"硬边界 / 缺少授权","停止动作，必要时可信确认","red","shield",15,9); add_node(s,630,445,300,100,"规划偏差 / 目标错误","指出原因码与相关字段","orange","review",15,9)
    add_node(s,270,600,300,100,"证据不足 / 资源未定","列出证据类别与观察引用","orange","database",15,9); add_node(s,630,600,300,100,"审查协议技术错误","格式错误或截断最多纠正一次","gray","doc",15,9)
    add_node(s,330,770,540,95,"反馈不增加权限","不生成替代参数，不把控制器反馈当用户指令","teal","lock",18,10); add_arrow(s,[(600,865),(600,965)],"orange")
    add_node(s,350,965,500,92,"行动模型受限重规划","修正参数、补充必要证据或继续独立步骤","orange","brain",18,10); add_arrow(s,[(600,1057),(600,1100)])
    add_node(s,350,1100,500,92,"预算与重复检查","每类修复、总拒绝、轮数与时间均有上限","red","clock",18,10); add_arrow(s,[(600,1192),(600,1235)])
    add_node(s,385,1235,430,88,"产生新依据且仍在预算？","相同拒绝不能靠换工具重置","blue","review",17,10)
    add_arrow(s,[(385,1279),(180,1279),(180,1355)],"red"); add_arrow(s,[(815,1279),(1020,1279),(1020,1355)],"teal")
    add_node(s,55,1355,300,70,"否：停止 / 可信确认",tone="red",icon="stop",title_size=14); add_node(s,865,1355,300,70,"是：重新走完整授权链",tone="teal",icon="check",title_size=13)
    add_arrow(s,[(1020,1355),(1120,1355),(1120,1010),(850,1010)],"orange"); add_text(s,960,1080,150,24,"新调用重新审查",11,"orange",True,PP_ALIGN.CENTER)
    footer(s,"硬性阻断不会因重规划而放宽，补证查询和修正后的调用也必须重新审核。")


def slide5(prs):
    s=add_base(prs,"ICB-Guard：可信约束与宿主记录","为检查、审查和执行提供完整性受保护的依据",5,"TRUSTED HOST · 约束与记录层")
    add_node(s,65,205,250,82,"原始用户请求","可信入口锚定","blue","user",15,9); add_node(s,350,205,250,82,"管理员约束","能力 / 规则 / 合同","blue","shield",15,9); add_node(s,635,205,250,82,"可信确认","独立审批身份","blue","check",15,9); add_node(s,920,205,215,82,"宿主状态","时钟 / session / 资源","blue","clock",14,8)
    for x in (190,475,760,1028): add_arrow(s,[(x,287),(x,340),(600,340),(600,390)])
    add_node(s,350,390,500,90,"认证、固定版本并建立快照","不接受行动模型自报的权限、身份或状态","blue","lock",17,10); add_arrow(s,[(600,480),(600,530)])
    add_group(s,245,530,710,575,"宿主管理的可信记录层")
    add_node(s,305,585,590,88,"任务与配置快照","原始请求哈希 · 工具合同 · 策略版本","blue","anchor",17,10); add_node(s,305,705,590,88,"资源来源台账","RID · 账户 · 实体版本 · 字段绑定","teal","database",17,10); add_node(s,305,825,590,88,"审查证据图","EID · 类型化事实 · 有限推导 · 数据用途","purple","review",17,10); add_node(s,305,945,590,88,"决策与执行回执","允许 / 拒绝 · 前后状态 · 实际结果","teal","doc",17,10)
    for y in (673,793,913): add_arrow(s,[(600,y),(600,y+32)],"teal")
    add_node(s,45,680,230,110,"外部工具返回","内容仍不可信\n宿主只登记来源与哈希","purple","eye",14,8); add_text(s,65,648,190,22,"可能包含注入",10,"purple",True,PP_ALIGN.CENTER); add_arrow(s,[(275,735),(305,735)],"purple")
    add_arrow(s,[(600,1033),(600,1145)]); add_node(s,375,1145,450,88,"发布受限引用","RID 是身份引用，EID 是证据引用","blue","ticket",17,10)
    add_arrow(s,[(375,1189),(190,1189),(190,1280)],"blue"); add_arrow(s,[(600,1233),(600,1280)],"purple"); add_arrow(s,[(825,1189),(1010,1189),(1010,1280)],"teal")
    add_node(s,60,1280,260,78,"供硬约束检验",tone="blue",icon="shield",title_size=14); add_node(s,470,1280,260,78,"供语义审查",tone="purple",icon="review",title_size=14); add_node(s,880,1280,260,78,"供执行前复核",tone="teal",icon="lock",title_size=14)
    add_arrow(s,[(1010,1358),(1010,1395),(905,1395),(905,1033)],"teal",True); add_text(s,1015,1380,130,22,"执行后更新回执",10,"teal",True,PP_ALIGN.CENTER)
    footer(s,"记录来源可信不代表外部内容真实，也不代表数据用途已经获得授权。")


def main():
    prs = Presentation()
    prs.slide_width = Inches(12)
    prs.slide_height = Inches(15)
    slide1(prs); slide2(prs); slide3(prs); slide4(prs); slide5(prs)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUT)
    print(OUT)


if __name__ == "__main__":
    main()
