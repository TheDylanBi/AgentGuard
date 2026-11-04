param(
    [string]$OutputPath = "F:/Code/MLLM Agent/output/pptx/icb_guard_five_module_flows_editable.pptx",
    [string]$PreviewDir = "F:/Code/MLLM Agent/tmp/pptx_guard_preview"
)

$ErrorActionPreference = "Stop"
$script:Scale = 0.72
$script:FontName = "Microsoft YaHei"
$script:SymbolFont = "Segoe UI Symbol"
$script:Counter = 0

function U([double]$Value) { return $Value * $script:Scale }
function RGB([int]$R, [int]$G, [int]$B) { return $R + 256 * $G + 65536 * $B }

$C = @{
    navy = RGB 8 42 89; blue = RGB 20 118 232; blue2 = RGB 46 95 184
    teal = RGB 0 165 160; orange = RGB 255 107 0; red = RGB 239 23 76
    purple = RGB 103 66 211; gray = RGB 113 131 154; white = RGB 255 255 255
    shadow = RGB 221 232 245
}

function ToneColor([string]$Tone) { return $C[$Tone] }

function Add-Text {
    param($Slide, [double]$X, [double]$Y, [double]$W, [double]$H,
          [string]$Text, [double]$Size = 18, [string]$Tone = "navy",
          [bool]$Bold = $false, [int]$Align = 1, [int]$VAnchor = 1,
          [string]$Font = $script:FontName)
    $shape = $Slide.Shapes.AddTextbox(1, (U $X), (U $Y), (U $W), (U $H))
    $shape.Name = "Text $([System.Threading.Interlocked]::Increment([ref]$script:Counter))"
    $shape.Fill.Visible = 0; $shape.Line.Visible = 0
    $shape.TextFrame2.MarginLeft = 0; $shape.TextFrame2.MarginRight = 0
    $shape.TextFrame2.MarginTop = 0; $shape.TextFrame2.MarginBottom = 0
    $shape.TextFrame2.WordWrap = -1; $shape.TextFrame2.AutoSize = 0
    $shape.TextFrame2.VerticalAnchor = $VAnchor
    $range = $shape.TextFrame2.TextRange
    $range.Text = $Text
    $range.Font.Name = $Font; $range.Font.NameFarEast = $script:FontName
    $range.Font.Size = $Size; $range.Font.Bold = $(if ($Bold) { -1 } else { 0 })
    $range.Font.Fill.ForeColor.RGB = (ToneColor $Tone)
    $range.ParagraphFormat.Alignment = $Align
    return $shape
}

function Add-RoundRect {
    param($Slide, [double]$X, [double]$Y, [double]$W, [double]$H,
          [string]$Tone = "blue", [bool]$Dashed = $false,
          [bool]$Fill = $true, [double]$Weight = 2.2, [bool]$Shadow = $false)
    if ($Shadow) {
        $s = $Slide.Shapes.AddShape(5, (U ($X + 4)), (U ($Y + 5)), (U $W), (U $H))
        $s.Name = "Shadow $([System.Threading.Interlocked]::Increment([ref]$script:Counter))"
        $s.Fill.ForeColor.RGB = $C.shadow; $s.Fill.Transparency = 0.55
        $s.Line.Visible = 0
    }
    $shape = $Slide.Shapes.AddShape(5, (U $X), (U $Y), (U $W), (U $H))
    $shape.Name = "Rounded rectangle $([System.Threading.Interlocked]::Increment([ref]$script:Counter))"
    $shape.Fill.Visible = $(if ($Fill) { -1 } else { 0 })
    if ($Fill) { $shape.Fill.ForeColor.RGB = $C.white }
    $shape.Line.Visible = -1; $shape.Line.ForeColor.RGB = (ToneColor $Tone)
    $shape.Line.Weight = $Weight
    if ($Dashed) { $shape.Line.DashStyle = 4 }
    return $shape
}

function Add-LineShape {
    param($Slide, [double]$X1, [double]$Y1, [double]$X2, [double]$Y2,
          [string]$Tone = "blue", [double]$Weight = 2.2,
          [bool]$Arrow = $false, [bool]$Dashed = $false)
    $line = $Slide.Shapes.AddLine((U $X1), (U $Y1), (U $X2), (U $Y2))
    $line.Name = "Connector $([System.Threading.Interlocked]::Increment([ref]$script:Counter))"
    $line.Line.ForeColor.RGB = (ToneColor $Tone); $line.Line.Weight = $Weight
    if ($Dashed) { $line.Line.DashStyle = 4 }
    if ($Arrow) { $line.Line.EndArrowheadStyle = 3 }
    return $line
}

function Add-Arrow {
    param($Slide, [array]$Points, [string]$Tone = "blue", [bool]$Dashed = $false,
          [double]$Weight = 2.2)
    for ($i = 0; $i -lt $Points.Count - 1; $i++) {
        $a = $Points[$i]; $b = $Points[$i + 1]
        Add-LineShape $Slide $a[0] $a[1] $b[0] $b[1] $Tone $Weight ($i -eq $Points.Count - 2) $Dashed | Out-Null
    }
}

function Add-Icon {
    param($Slide, [double]$X, [double]$Y, [double]$S, [string]$Kind, [string]$Tone)
    $col = ToneColor $Tone
    switch ($Kind) {
        "user" {
            $a=$Slide.Shapes.AddShape(9,(U ($X+$S*.36)),(U ($Y+$S*.05)),(U ($S*.28)),(U ($S*.28)))
            $a.Fill.ForeColor.RGB=$col;$a.Line.Visible=0
            $b=$Slide.Shapes.AddShape(5,(U ($X+$S*.20)),(U ($Y+$S*.48)),(U ($S*.60)),(U ($S*.42)))
            $b.Fill.ForeColor.RGB=$col;$b.Line.Visible=0
        }
        "database" {
            $a=$Slide.Shapes.AddShape(13,(U ($X+$S*.14)),(U ($Y+$S*.10)),(U ($S*.72)),(U ($S*.78)))
            $a.Fill.Visible=0;$a.Line.ForeColor.RGB=$col;$a.Line.Weight=2.2
        }
        "check" {
            $a=$Slide.Shapes.AddShape(9,(U ($X+$S*.08)),(U ($Y+$S*.08)),(U ($S*.84)),(U ($S*.84)))
            $a.Fill.ForeColor.RGB=$col;$a.Line.Visible=0
            Add-Text $Slide ($X+$S*.18) ($Y+$S*.10) ($S*.65) ($S*.65) "✓" ($S*.45) "white" $true 2 3 $script:SymbolFont | Out-Null
        }
        "stop" {
            $a=$Slide.Shapes.AddShape(9,(U ($X+$S*.08)),(U ($Y+$S*.08)),(U ($S*.84)),(U ($S*.84)))
            $a.Fill.Visible=0;$a.Line.ForeColor.RGB=$col;$a.Line.Weight=2.5
            Add-LineShape $Slide ($X+$S*.22) ($Y+$S*.22) ($X+$S*.78) ($Y+$S*.78) $Tone 2.8 | Out-Null
        }
        "shield" {
            $a=$Slide.Shapes.AddShape(51,(U ($X+$S*.14)),(U ($Y+$S*.06)),(U ($S*.72)),(U ($S*.84)))
            $a.Fill.ForeColor.RGB=$col;$a.Line.Visible=0;$a.Rotation=180
            Add-Text $Slide ($X+$S*.30) ($Y+$S*.23) ($S*.40) ($S*.45) "!" ($S*.31) "white" $true 2 3 | Out-Null
        }
        "lock" {
            $ring=$Slide.Shapes.AddShape(9,(U ($X+$S*.24)),(U ($Y+$S*.08)),(U ($S*.52)),(U ($S*.52)))
            $ring.Fill.Visible=0;$ring.Line.ForeColor.RGB=$col;$ring.Line.Weight=2.2
            $body=$Slide.Shapes.AddShape(5,(U ($X+$S*.18)),(U ($Y+$S*.40)),(U ($S*.64)),(U ($S*.48)))
            $body.Fill.ForeColor.RGB=$col;$body.Line.Visible=0
            Add-Text $Slide ($X+$S*.38) ($Y+$S*.44) ($S*.24) ($S*.32) "•" ($S*.28) "white" $true 2 3 | Out-Null
        }
        "flow" {
            Add-LineShape $Slide ($X+$S*.27) ($Y+$S*.52) ($X+$S*.72) ($Y+$S*.25) $Tone 2.1 | Out-Null
            Add-LineShape $Slide ($X+$S*.27) ($Y+$S*.52) ($X+$S*.72) ($Y+$S*.76) $Tone 2.1 | Out-Null
            foreach($p in @(@(.18,.43),@(.63,.16),@(.63,.67))){
                $o=$Slide.Shapes.AddShape(9,(U ($X+$S*$p[0])),(U ($Y+$S*$p[1])),(U ($S*.18)),(U ($S*.18)))
                $o.Fill.ForeColor.RGB=$col;$o.Line.Visible=0
            }
        }
        "eye" {
            $a=$Slide.Shapes.AddShape(9,(U ($X+$S*.08)),(U ($Y+$S*.26)),(U ($S*.84)),(U ($S*.48)))
            $a.Fill.Visible=0;$a.Line.ForeColor.RGB=$col;$a.Line.Weight=2.2
            $b=$Slide.Shapes.AddShape(9,(U ($X+$S*.39)),(U ($Y+$S*.39)),(U ($S*.22)),(U ($S*.22)))
            $b.Fill.ForeColor.RGB=$col;$b.Line.Visible=0
        }
        "clock" {
            $a=$Slide.Shapes.AddShape(9,(U ($X+$S*.10)),(U ($Y+$S*.10)),(U ($S*.80)),(U ($S*.80)))
            $a.Fill.Visible=0;$a.Line.ForeColor.RGB=$col;$a.Line.Weight=2.2
            Add-LineShape $Slide ($X+$S*.50) ($Y+$S*.50) ($X+$S*.50) ($Y+$S*.25) $Tone 2.1 | Out-Null
            Add-LineShape $Slide ($X+$S*.50) ($Y+$S*.50) ($X+$S*.70) ($Y+$S*.62) $Tone 2.1 | Out-Null
        }
        "ticket" {
            $a=$Slide.Shapes.AddShape(5,(U ($X+$S*.10)),(U ($Y+$S*.25)),(U ($S*.80)),(U ($S*.50)))
            $a.Fill.Visible=0;$a.Line.ForeColor.RGB=$col;$a.Line.Weight=2.2
            $l=Add-LineShape $Slide ($X+$S*.50) ($Y+$S*.30) ($X+$S*.50) ($Y+$S*.70) $Tone 1.6 $false $true
        }
        "wrench" {
            Add-Text $Slide $X ($Y-$S*.02) $S $S "⚒" ($S*.62) $Tone $true 2 3 $script:SymbolFont | Out-Null
        }
        "anchor" {
            Add-Text $Slide $X ($Y-$S*.02) $S $S "⚓" ($S*.62) $Tone $true 2 3 $script:SymbolFont | Out-Null
        }
        "brain" {
            foreach($p in @(@(.18,.23),@(.40,.12),@(.60,.24),@(.26,.51),@(.50,.56),@(.36,.76))){
                $o=$Slide.Shapes.AddShape(9,(U ($X+$S*$p[0])),(U ($Y+$S*$p[1])),(U ($S*.27)),(U ($S*.27)))
                $o.Fill.Visible=0;$o.Line.ForeColor.RGB=$col;$o.Line.Weight=2.0
            }
        }
        default {
            $r=$Slide.Shapes.AddShape(1,(U ($X+$S*.18)),(U ($Y+$S*.08)),(U ($S*.62)),(U ($S*.80)))
            $r.Fill.Visible=0;$r.Line.ForeColor.RGB=$col;$r.Line.Weight=2.2
            foreach($yy in @(.38,.53,.68)){ Add-LineShape $Slide ($X+$S*.29) ($Y+$S*$yy) ($X+$S*.69) ($Y+$S*$yy) $Tone 1.5 | Out-Null }
            if($Kind -eq "review"){
                $o=$Slide.Shapes.AddShape(9,(U ($X+$S*.62)),(U ($Y+$S*.62)),(U ($S*.27)),(U ($S*.27)))
                $o.Fill.Visible=0;$o.Line.ForeColor.RGB=$col;$o.Line.Weight=1.9
                Add-LineShape $Slide ($X+$S*.82) ($Y+$S*.82) ($X+$S*.96) ($Y+$S*.96) $Tone 1.9 | Out-Null
            }
        }
    }
}

function Add-Node {
    param($Slide,[double]$X,[double]$Y,[double]$W,[double]$H,[string]$Title,
          [string]$Subtitle="",[string]$Tone="blue",[string]$Icon="doc",
          [double]$TitleSize=18,[double]$SubtitleSize=11)
    Add-RoundRect $Slide $X $Y $W $H $Tone $false $true 2.2 $true | Out-Null
    $s=[Math]::Min(52,$H-24); Add-Icon $Slide ($X+22) ($Y+($H-$s)/2) $s $Icon $Tone
    $tx=$X+22+$s+18
    if($Subtitle){
        $titleTone=$(if($Tone -in @("red","orange")){$Tone}else{"navy"})
        Add-Text $Slide $tx ($Y+17) ($W-($tx-$X)-18) 30 $Title $TitleSize $titleTone $true 1 1 | Out-Null
        $subTone=$(if($Tone -in @("red","orange")){$Tone}else{"gray"})
        Add-Text $Slide $tx ($Y+$H-36) ($W-($tx-$X)-18) 28 $Subtitle $SubtitleSize $subTone $false 1 1 | Out-Null
    } else {
        $titleTone=$(if($Tone -in @("red","orange")){$Tone}else{"navy"})
        Add-Text $Slide $tx $Y ($W-($tx-$X)-18) $H $Title $TitleSize $titleTone $true 1 3 | Out-Null
    }
}

function Add-Boundary {
    param($Slide,[string]$Label)
    Add-RoundRect $Slide 28 170 1144 1262 "blue" $true $false 1.8 $false | Out-Null
    Add-Text $Slide 66 184 440 24 $Label 13 "blue" $true 1 1 | Out-Null
}

function Add-Group {
    param($Slide,[double]$X,[double]$Y,[double]$W,[double]$H,[string]$Label)
    Add-RoundRect $Slide $X $Y $W $H "teal" $true $false 1.8 $false | Out-Null
    Add-Text $Slide $X ($Y+13) $W 32 $Label 17 "teal" $true 2 1 | Out-Null
}

function Add-Base {
    param($Presentation,[string]$Title,[string]$Subtitle,[int]$Index,[string]$BoundaryLabel)
    $slide=$Presentation.Slides.Add($Presentation.Slides.Count+1,12)
    $slide.FollowMasterBackground=0;$slide.Background.Fill.ForeColor.RGB=$C.white
    Add-Text $slide 120 30 960 58 $Title 29 "navy" $true 2 1 | Out-Null
    Add-Text $slide 180 84 840 38 $Subtitle 16 "blue2" $true 2 1 | Out-Null
    Add-Text $slide 1100 25 55 30 "$Index/5" 12 "gray" $true 3 1 | Out-Null
    Add-Boundary $slide $BoundaryLabel
    return $slide
}

function Add-Footer { param($Slide,[string]$Text)
    Add-Text $Slide 110 1444 980 28 $Text 11 "gray" $true 2 1 | Out-Null
}

function Build-Slide1($P) {
    $s=Add-Base $P "ICB-Guard：硬约束与来源检验" "从候选调用到确定性边界检查" 1 "TRUSTED HOST · 硬约束检查域"
    Add-Node $s 390 120 420 86 "候选工具调用" "工具名 + 模型参数" "blue" "brain" 19 12
    Add-Arrow $s @(@(600,206),@(600,248))
    Add-Node $s 365 248 470 92 "完整参数规范化" "Schema · 类型 · 默认值 · 别名" "blue" "doc" 18 11
    Add-Arrow $s @(@(600,340),@(600,380))
    Add-Node $s 365 380 470 92 "资源与目的地解析" "RID / 原生 ID · 账户 · 版本 · TTL" "blue" "flow" 18 11
    Add-Arrow $s @(@(600,472),@(600,522))
    Add-Group $s 275 522 650 570 "硬约束与来源检验"
    $rows=@(
        @(570,"工具身份与能力","固定 Schema · 角色 · 能力证书 · 作用域","shield"),
        @(690,"业务与资源边界","路径 / 金额 / 账户限制 · 业务禁令","lock"),
        @(810,"数据流与污染限制","来源 · 收件人 · 披露对象 · taint","flow"),
        @(930,"来源证明与新鲜度","实体 / 字段 / 账户 / 状态匹配","database")
    )
    foreach($r in $rows){Add-Node $s 330 $r[0] 540 88 $r[1] $r[2] "teal" $r[3] 17 10}
    foreach($y in @(658,778,898)){Add-Arrow $s @(@(600,$y),@(600,$y+32)) "teal"}
    Add-Arrow $s @(@(600,1018),@(600,1135))
    Add-Node $s 395 1135 410 90 "检查结果" "PASS 只表示边界与来源成立" "blue" "review" 18 11
    Add-Text $s 455 1106 290 24 "PASS ≠ 已获任务授权" 13 "orange" $true 2 1 | Out-Null
    Add-Arrow $s @(@(395,1180),@(210,1180),@(210,1260)) "red"
    Add-Arrow $s @(@(600,1225),@(600,1260)) "orange"
    Add-Arrow $s @(@(805,1180),@(990,1180),@(990,1260)) "teal"
    Add-Node $s 75 1260 270 80 "硬冲突：阻断" "" "red" "stop" 15
    Add-Node $s 465 1260 270 80 "缺证据：补证" "" "orange" "wrench" 15
    Add-Node $s 855 1260 270 80 "PASS：语义审查" "" "teal" "check" 15
    Add-Footer $s "来源证明只说明参数从哪里来，不存在硬检查通过后直接执行的旁路。"
}

function Build-Slide2($P) {
    $s=Add-Base $P "ICB-Guard：独立语义审查" "逐次判断具体动作是否符合原始用户授权" 2 "INDEPENDENT REVIEW · 分离上下文"
    Add-Node $s 80 205 300 88 "原始请求锚点" "工具输出不能改写" "blue" "anchor" 16 10
    Add-Node $s 450 205 300 88 "规范化语义动作" "操作 · 目标 · 完整参数" "teal" "doc" 16 10
    Add-Node $s 820 205 300 88 "宿主证据与历史" "EID · 来源 · 执行回执" "purple" "doc" 16 10
    foreach($x in @(230,600,970)){Add-Arrow $s @(@($x,293),@($x,340),@(600,340),@(600,382))}
    Add-Node $s 345 382 510 96 "构造本次审查包" "call_id · 状态哈希 · data-use scope" "blue" "doc" 18 11
    Add-Arrow $s @(@(600,478),@(600,535))
    Add-Group $s 270 535 660 435 "独立语义审查器"
    Add-Node $s 330 590 540 92 "判断任务授权" "操作 · 目标 · 范围 · 数据用途" "purple" "brain" 18 11
    Add-Arrow $s @(@(600,682),@(600,724)) "purple"
    Add-Node $s 330 724 540 92 "返回最小化决定" "decision · code · fields · evidence_ids" "purple" "review" 18 11
    Add-Arrow $s @(@(600,816),@(600,858)) "purple"
    Add-Node $s 330 858 540 88 "宿主严格校验协议" "证据引用有效，绑定哈希由宿主构造" "blue" "shield" 17 10
    Add-Arrow $s @(@(600,970),@(600,1040))
    Add-Node $s 400 1040 400 88 "有效决定？" "无效结构最多技术纠正一次" "blue" "review" 18 10
    Add-Arrow $s @(@(400,1084),@(190,1084),@(190,1185)) "red"
    Add-Arrow $s @(@(600,1128),@(600,1185)) "orange"
    Add-Arrow $s @(@(800,1084),@(1010,1084),@(1010,1185)) "teal"
    Add-Node $s 55 1185 270 78 "DENY：关闭路径" "" "red" "stop" 14
    Add-Node $s 465 1185 270 78 "NEEDS_EVIDENCE" "" "orange" "wrench" 13
    Add-Node $s 875 1185 270 78 "ALLOW + 数据用途允许" "" "teal" "check" 13
    Add-Node $s 395 1305 410 78 "下一阶段：执行前绑定复核" "ALLOW 不能覆盖硬约束" "teal" "lock" 15 9
    Add-Arrow $s @(@(1010,1263),@(1010,1280),@(600,1280),@(600,1305)) "teal"
    Add-Node $s 940 700 200 90 "技术错误" "失败则关闭执行" "gray" "stop" 14 9
    Add-Arrow $s @(@(930,900),@(1065,900),@(1065,790)) "gray" $true
    Add-Footer $s "独立上下文降低影响面，但不保证审查模型对注入免疫，语义判断仍可能出错。"
}

function Build-Slide3($P) {
    $s=Add-Base $P "ICB-Guard：执行前绑定复核" "保证允许动作与实际副作用对象保持一致" 3 "CONTROLLED EXECUTION · 绑定与复核域"
    Add-Node $s 390 120 420 86 "语义审查 ALLOW" "只覆盖当前候选调用" "teal" "check" 18 11
    Add-Arrow $s @(@(600,206),@(600,250)) "teal"
    Add-Node $s 350 250 500 92 "构造精确执行绑定" "工具 · 完整参数 · call_id · session · epoch" "blue" "lock" 18 10
    Add-Arrow $s @(@(600,342),@(600,386))
    Add-Node $s 350 386 500 92 "签发短期一次性凭据" "Schema · 证据 · 状态 · 资源快照哈希" "blue" "ticket" 18 10
    Add-Arrow $s @(@(600,478),@(600,525))
    Add-Group $s 260 525 680 570 "执行前重新取得当前状态"
    $rows=@(
        @(575,"动作绑定复核","工具、参数、调用 ID 未变化","doc"),
        @(695,"资源绑定复核","身份、账户、版本、内容状态一致","database"),
        @(815,"安全边界复核","能力、业务、数据流、证据仍有效","shield"),
        @(935,"执行通道复核","受信宿主与已审核工具适配器","lock")
    )
    foreach($r in $rows){Add-Node $s 320 $r[0] 560 88 $r[1] $r[2] "teal" $r[3] 17 10}
    foreach($y in @(663,783,903)){Add-Arrow $s @(@(600,$y),@(600,$y+32)) "teal"}
    Add-Arrow $s @(@(600,1023),@(600,1140))
    Add-Node $s 390 1140 420 88 "绑定仍有效？" "过期、重放或状态变化均拒绝" "blue" "review" 18 10
    Add-Arrow $s @(@(390,1184),@(175,1184),@(175,1260)) "red"
    Add-Arrow $s @(@(810,1184),@(1025,1184),@(1025,1260)) "teal"
    Add-Node $s 55 1260 300 80 "失效：重新授权" "" "red" "stop" 15
    Add-Node $s 865 1260 300 80 "有效：消费凭据" "" "teal" "ticket" 15
    Add-Node $s 450 1260 300 80 "宿主执行确切动作" "同一参数 / 资源句柄" "blue" "wrench" 14 9
    Add-Arrow $s @(@(865,1300),@(750,1300)) "teal"
    Add-Arrow $s @(@(600,1340),@(600,1370)) "teal"
    Add-Node $s 420 1370 360 62 "记录前后状态与结果" "成功或失败均不可重放" "purple" "doc" 13 8
    Add-Footer $s "这是至多一次执行尝试，不等于远程业务事务的 exactly-once 成功或崩溃原子性。"
}

function Build-Slide4($P) {
    $s=Add-Base $P "ICB-Guard：受限纠偏反馈" "拒绝后帮助合法任务恢复，同时不扩大权限" 4 "BOUNDED RECOVERY · 反馈与重规划"
    Add-Node $s 390 120 420 86 "调用未执行" "deny / needs_evidence / 技术错误" "blue" "stop" 18 10
    Add-Arrow $s @(@(600,206),@(600,250))
    Add-Node $s 390 250 420 88 "分类失败原因" "硬边界 · 规划偏差 · 证据 · 协议" "blue" "review" 18 10
    Add-Arrow $s @(@(600,338),@(600,390))
    Add-Group $s 220 390 760 545 "固定模板反馈：只给原因与修复边界"
    Add-Node $s 270 445 300 100 "硬边界 / 缺少授权" "停止动作，必要时可信确认" "red" "shield" 15 9
    Add-Node $s 630 445 300 100 "规划偏差 / 目标错误" "指出原因码与相关字段" "orange" "review" 15 9
    Add-Node $s 270 600 300 100 "证据不足 / 资源未定" "列出证据类别与观察引用" "orange" "database" 15 9
    Add-Node $s 630 600 300 100 "审查协议技术错误" "格式错误或截断最多纠正一次" "gray" "doc" 15 9
    Add-Node $s 330 770 540 95 "反馈不增加权限" "不生成替代参数，不把控制器反馈当用户指令" "teal" "lock" 18 10
    Add-Arrow $s @(@(600,865),@(600,965)) "orange"
    Add-Node $s 350 965 500 92 "行动模型受限重规划" "修正参数、补充必要证据或继续独立步骤" "orange" "brain" 18 10
    Add-Arrow $s @(@(600,1057),@(600,1100))
    Add-Node $s 350 1100 500 92 "预算与重复检查" "每类修复、总拒绝、轮数与时间均有上限" "red" "clock" 18 10
    Add-Arrow $s @(@(600,1192),@(600,1235))
    Add-Node $s 385 1235 430 88 "产生新依据且仍在预算？" "相同拒绝不能靠换工具重置" "blue" "review" 17 10
    Add-Arrow $s @(@(385,1279),@(180,1279),@(180,1355)) "red"
    Add-Arrow $s @(@(815,1279),@(1020,1279),@(1020,1355)) "teal"
    Add-Node $s 55 1355 300 70 "否：停止 / 可信确认" "" "red" "stop" 14
    Add-Node $s 865 1355 300 70 "是：重新走完整授权链" "" "teal" "check" 13
    Add-Arrow $s @(@(1020,1355),@(1120,1355),@(1120,1010),@(850,1010)) "orange"
    Add-Text $s 960 1080 150 24 "新调用重新审查" 11 "orange" $true 2 1 | Out-Null
    Add-Footer $s "硬性阻断不会因重规划而放宽，补证查询和修正后的调用也必须重新审核。"
}

function Build-Slide5($P) {
    $s=Add-Base $P "ICB-Guard：可信约束与宿主记录" "为检查、审查和执行提供完整性受保护的依据" 5 "TRUSTED HOST · 约束与记录层"
    Add-Node $s 65 205 250 82 "原始用户请求" "可信入口锚定" "blue" "user" 15 9
    Add-Node $s 350 205 250 82 "管理员约束" "能力 / 规则 / 合同" "blue" "shield" 15 9
    Add-Node $s 635 205 250 82 "可信确认" "独立审批身份" "blue" "check" 15 9
    Add-Node $s 920 205 215 82 "宿主状态" "时钟 / session / 资源" "blue" "clock" 14 8
    foreach($x in @(190,475,760,1028)){Add-Arrow $s @(@($x,287),@($x,340),@(600,340),@(600,390))}
    Add-Node $s 350 390 500 90 "认证、固定版本并建立快照" "不接受行动模型自报的权限、身份或状态" "blue" "lock" 17 10
    Add-Arrow $s @(@(600,480),@(600,530))
    Add-Group $s 245 530 710 575 "宿主管理的可信记录层"
    Add-Node $s 305 585 590 88 "任务与配置快照" "原始请求哈希 · 工具合同 · 策略版本" "blue" "anchor" 17 10
    Add-Node $s 305 705 590 88 "资源来源台账" "RID · 账户 · 实体版本 · 字段绑定" "teal" "database" 17 10
    Add-Node $s 305 825 590 88 "审查证据图" "EID · 类型化事实 · 有限推导 · 数据用途" "purple" "review" 17 10
    Add-Node $s 305 945 590 88 "决策与执行回执" "允许 / 拒绝 · 前后状态 · 实际结果" "teal" "doc" 17 10
    foreach($y in @(673,793,913)){Add-Arrow $s @(@(600,$y),@(600,$y+32)) "teal"}
    Add-Node $s 45 680 230 110 "外部工具返回" "内容仍不可信`n宿主只登记来源与哈希" "purple" "eye" 14 8
    Add-Text $s 65 648 190 22 "可能包含注入" 10 "purple" $true 2 1 | Out-Null
    Add-Arrow $s @(@(275,735),@(305,735)) "purple"
    Add-Arrow $s @(@(600,1033),@(600,1145))
    Add-Node $s 375 1145 450 88 "发布受限引用" "RID 是身份引用，EID 是证据引用" "blue" "ticket" 17 10
    Add-Arrow $s @(@(375,1189),@(190,1189),@(190,1280)) "blue"
    Add-Arrow $s @(@(600,1233),@(600,1280)) "purple"
    Add-Arrow $s @(@(825,1189),@(1010,1189),@(1010,1280)) "teal"
    Add-Node $s 60 1280 260 78 "供硬约束检验" "" "blue" "shield" 14
    Add-Node $s 470 1280 260 78 "供语义审查" "" "purple" "review" 14
    Add-Node $s 880 1280 260 78 "供执行前复核" "" "teal" "lock" 14
    Add-Arrow $s @(@(1010,1358),@(1010,1395),@(905,1395),@(905,1033)) "teal" $true
    Add-Text $s 1015 1380 130 22 "执行后更新回执" 10 "teal" $true 2 1 | Out-Null
    Add-Footer $s "记录来源可信不代表外部内容真实，也不代表数据用途已经获得授权。"
}

$outputDirectory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $PreviewDir | Out-Null

$ppt = New-Object -ComObject PowerPoint.Application
try {
    $ppt.Visible = -1
    $presentation = $ppt.Presentations.Add()
    $presentation.PageSetup.SlideWidth = (U 1200)
    $presentation.PageSetup.SlideHeight = (U 1500)
    Build-Slide1 $presentation
    Build-Slide2 $presentation
    Build-Slide3 $presentation
    Build-Slide4 $presentation
    Build-Slide5 $presentation
    for($i=1;$i -le $presentation.Slides.Count;$i++){
        $preview = Join-Path $PreviewDir ("slide-{0:D2}.png" -f $i)
        $presentation.Slides.Item($i).Export($preview,"PNG",1200,1500)
    }
    $presentation.SaveAs($OutputPath,24)
    $presentation.Close()
}
finally {
    $ppt.Quit()
    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($ppt) | Out-Null
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

Write-Output $OutputPath
