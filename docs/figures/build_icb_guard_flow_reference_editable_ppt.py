from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".codex-pptx-build" / "vendor"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pptx import Presentation
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches

from build_guard_module_flows_editable_ppt import (
    C,
    add_arrow,
    add_group,
    add_icon,
    add_node,
    add_round_rect,
    add_text,
)


OUT = ROOT / "output" / "pptx" / "icb_guard_review_flow_editable.pptx"


def label(slide, x, y, w, text, tone="blue", size=11):
    add_text(slide, x, y, w, 26, text, size, tone, True,
             PP_ALIGN.CENTER, MSO_ANCHOR.MIDDLE)


def build_slide(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    bg = s.background.fill
    bg.solid()
    bg.fore_color.rgb = C["white"]

    add_text(s, 115, 24, 970, 60, "ICB-Guard：逐次授权与受限纠偏",
             29, "navy", True, PP_ALIGN.CENTER, MSO_ANCHOR.TOP)
    add_text(s, 260, 84, 680, 38, "review 模式流程",
             17, "blue2", True, PP_ALIGN.CENTER, MSO_ANCHOR.TOP)

    add_node(s, 390, 128, 420, 82, "用户请求", tone="blue", icon="user", title_size=20)
    add_arrow(s, [(600, 210), (600, 246)], "blue")
    add_node(s, 390, 246, 420, 82, "原始请求锚定", tone="blue", icon="doc", title_size=19)

    add_round_rect(s, 18, 350, 1164, 1088, "blue", True, False, 1.8)

    add_node(s, 28, 420, 300, 88, "可信约束与宿主记录",
             "规则 / 工具合同 / 来源证据", "blue", "database", 15, 9)
    add_arrow(s, [(328, 464), (365, 464)], "blue")

    add_arrow(s, [(600, 328), (600, 378), (575, 378), (575, 420)], "blue")
    add_node(s, 365, 420, 420, 88, "上下文管理",
             "原始请求 · 历史观察 · 执行记录", "blue", "doc", 18, 10)
    add_arrow(s, [(575, 508), (575, 550)], "blue")
    add_node(s, 365, 550, 420, 88, "行动模型",
             "推理 / 规划", "blue", "brain", 19, 11)

    add_round_rect(s, 790, 370, 360, 420, "teal", True, False, 1.8)
    add_text(s, 805, 380, 330, 34, "ICB-Guard 授权链",
             18, "teal", True, PP_ALIGN.CENTER, MSO_ANCHOR.TOP)

    add_node(s, 815, 425, 310, 92, "硬约束与来源检验",
             "能力 · 规则 · 来源 · 参数数据", "teal", "shield", 16, 9)
    add_arrow(s, [(970, 517), (970, 552)], "teal")
    label(s, 985, 520, 135, "检查通过 ≠ 授权", "teal", 9)
    add_node(s, 815, 552, 310, 92, "独立语义审查",
             "用户意图 · 动作用途 · 数据披露", "teal", "review", 16, 9)
    add_arrow(s, [(970, 644), (970, 680)], "teal")
    label(s, 987, 648, 105, "允许", "teal", 9)
    add_node(s, 815, 680, 310, 92, "执行前绑定复核",
             "完整参数 · 资源状态 · 防重放", "teal", "lock", 16, 9)

    add_arrow(s, [(785, 594), (800, 594), (800, 471), (815, 471)], "blue")
    add_arrow(s, [(810, 292), (1070, 292), (1070, 370)], "blue")
    label(s, 765, 557, 105, "候选调用", "blue", 10)

    add_node(s, 360, 840, 390, 80, "工具执行",
             "经审核的工具适配器", "blue", "wrench", 18, 9)
    add_arrow(s, [(815, 726), (770, 726), (770, 880), (750, 880)], "teal")
    label(s, 625, 811, 110, "复核通过", "teal", 10)

    add_node(s, 790, 835, 225, 92, "受限纠偏反馈",
             "偏差字段 / 缺失证据", "orange", "wrench", 14, 8)
    add_node(s, 1025, 835, 145, 92, "停止",
             "请求可信确认", "red", "stop", 14, 8)
    add_arrow(s, [(915, 772), (915, 835)], "orange")
    add_arrow(s, [(1070, 772), (1098, 772), (1098, 835)], "red")
    label(s, 815, 795, 190, "未通过，可纠偏", "orange", 10)
    label(s, 1015, 795, 155, "硬性不通过", "red", 10)
    label(s, 808, 925, 205, "反馈不增加权限", "gray", 9)

    add_arrow(s, [(790, 880), (775, 880), (775, 660), (575, 660), (575, 638)], "orange")
    label(s, 525, 670, 260, "补证 / 重规划 / 重新审查", "orange", 11)

    add_arrow(s, [(555, 920), (555, 952)], "blue")
    label(s, 430, 923, 250, "经审核的工具适配器", "blue2", 9)
    add_arrow(s, [(555, 952), (300, 952), (300, 975)], "blue")
    add_arrow(s, [(555, 952), (555, 975)], "blue")
    add_arrow(s, [(555, 952), (810, 952), (810, 975)], "blue")
    add_node(s, 195, 975, 220, 76, "读取资源", tone="teal", icon="doc", title_size=15)
    add_node(s, 445, 975, 220, 76, "修改资源", tone="teal", icon="wrench", title_size=15)
    add_node(s, 695, 975, 230, 76, "发送 / 分享", tone="teal", icon="flow", title_size=15)

    add_arrow(s, [(305, 1051), (305, 1085), (555, 1085), (555, 1100)], "blue")
    add_arrow(s, [(555, 1051), (555, 1100)], "blue")
    add_arrow(s, [(810, 1051), (810, 1085), (555, 1085)], "blue")
    add_node(s, 350, 1100, 410, 82, "工具观察",
             "外部内容仍不可信", "purple", "eye", 18, 10)

    add_arrow(s, [(555, 1182), (555, 1228)], "blue")
    label(s, 430, 1190, 250, "准备结束", "blue", 10)
    add_node(s, 365, 1228, 420, 82, "一次完成核对",
             "核对遗漏与执行记录", "blue", "check", 18, 10)
    add_arrow(s, [(575, 1310), (575, 1350)], "blue")
    label(s, 590, 1315, 150, "完成核对", "blue", 9)
    add_node(s, 390, 1350, 370, 70, "最终答复", tone="teal", icon="check", title_size=18)

    add_arrow(s, [(350, 1140), (170, 1140), (170, 594), (365, 594)], "blue")
    add_arrow(s, [(365, 1269), (205, 1269), (205, 660), (365, 660)], "orange")
    add_text(s, 105, 518, 210, 50, "宿主登记来源\n与执行记录",
             10, "blue", True, PP_ALIGN.CENTER, MSO_ANCHOR.MIDDLE)
    add_arrow(s, [(170, 1140), (85, 1140), (85, 508)], "blue")
    label(s, 30, 1208, 230, "补充步骤重新审查", "orange", 10)

    add_text(s, 170, 1450, 860, 26,
             "语义判断可能出错；硬约束与绑定复核独立执行。图示为模拟宿主 review 流程。",
             10, "gray", True, PP_ALIGN.CENTER, MSO_ANCHOR.TOP)
    return s


def main():
    prs = Presentation()
    prs.slide_width = Inches(12)
    prs.slide_height = Inches(15)
    build_slide(prs)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUT)
    print(OUT)


if __name__ == "__main__":
    main()
