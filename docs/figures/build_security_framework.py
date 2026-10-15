"""Render implementation-grounded publication figures as vector PDF and SVG."""
from pathlib import Path
from html import escape
import math
import argparse
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.pdfbase.pdfmetrics import stringWidth

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output' / 'pdf'
OUT.mkdir(parents=True, exist_ok=True)
W, H = 1800, 1200
C = dict(ink='#172B3A', muted='#566875', line='#A5B3BD', blue='#32668C', bluebg='#EDF4F9',
         teal='#24796F', tealbg='#EDF7F3', amber='#A66B1B', amberbg='#FCF5E8',
         red='#A04749', redbg='#FBEFF0', graybg='#F5F7F8', white='#FFFFFF')
parser = argparse.ArgumentParser()
parser.add_argument('--pdf-name', default='icb_guard_security_framework.pdf')
args = parser.parse_args()
if Path(args.pdf_name).name != args.pdf_name or not args.pdf_name.endswith('.pdf'):
    parser.error('--pdf-name must be a PDF filename without directory components')
pdf = canvas.Canvas(str(OUT / args.pdf_name), pagesize=(W, H))
pdf.setTitle('ICB-Guard: Implemented Security Architecture and Decision Protocol')
pdf.setAuthor('Implementation-grounded framework diagram')
svgs = []
overflows = []


def color(key):
    return C.get(key, key)


def rect(x, y, w, h, fill='white', stroke='line', dash=False, radius=8, lw=1.3):
    pdf.setFillColor(HexColor(color(fill)))
    pdf.setStrokeColor(HexColor(color(stroke)))
    pdf.setLineWidth(lw)
    pdf.setDash([6, 4] if dash else [])
    pdf.roundRect(x, H-y-h, w, h, radius, fill=1, stroke=1)
    svgs.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{color(fill)}" stroke="{color(stroke)}" stroke-width="{lw}"'+(' stroke-dasharray="6 4"' if dash else '')+'/>')
    pdf.setDash([])


def text(x, y, value, size=18, bold=False, ink='ink', serif=False):
    font = ('Times-Bold' if bold else 'Times-Roman') if serif else ('Helvetica-Bold' if bold else 'Helvetica')
    pdf.setFont(font, size)
    pdf.setFillColor(HexColor(color(ink)))
    pdf.drawString(x, H-y, value)
    family = 'Times New Roman,serif' if serif else 'Arial,Helvetica,sans-serif'
    svgs.append(f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color(ink)}">{escape(value)}</text>')


def wrapped(x, y, value, width, size=17, leading=24, ink='ink', bold=False):
    font = 'Helvetica-Bold' if bold else 'Helvetica'
    for para in value.split('\n'):
        line = ''
        for word in para.split():
            test = (line+' '+word).strip()
            if stringWidth(test, font, size) > width and line:
                text(x, y, line, size, bold, ink)
                y += leading
                line = word
            else:
                line = test
        if line:
            text(x, y, line, size, bold, ink)
            y += leading
    return y


def card(x, y, w, h, title, body, tone='blue', size=17):
    rect(x, y, w, h, tone+'bg', tone)
    text(x+17, y+30, title, 19, True, tone)
    end = wrapped(x+17, y+58, body, w-34, size, size+7)
    if end-(size+7) > y+h-10:
        overflows.append((title, end, y+h))


def arrow(points, ink='muted', dashed=False, head=True, lw=1.8):
    pdf.setStrokeColor(HexColor(color(ink))); pdf.setLineWidth(lw)
    pdf.setDash([6,4] if dashed else [])
    path=pdf.beginPath(); path.moveTo(points[0][0],H-points[0][1])
    for x,y in points[1:]: path.lineTo(x,H-y)
    pdf.drawPath(path); pdf.setDash([])
    svgs.append(f'<polyline points="'+ ' '.join(f'{x},{y}' for x,y in points)+f'" fill="none" stroke="{color(ink)}" stroke-width="{lw}"'+(' stroke-dasharray="6 4"' if dashed else '')+'/>')
    if head:
        x,y=points[-1]; px,py=points[-2]; a=math.atan2(y-py,x-px)
        q=[(x,y),(x-10*math.cos(a)+4*math.sin(a),y-10*math.sin(a)-4*math.cos(a)),(x-10*math.cos(a)-4*math.sin(a),y-10*math.sin(a)+4*math.cos(a))]
        pdf.setFillColor(HexColor(color(ink)))
        p=pdf.beginPath();p.moveTo(q[0][0],H-q[0][1])
        for xx,yy in q[1:]:p.lineTo(xx,H-yy)
        p.close();pdf.drawPath(p,fill=1,stroke=0)
        svgs.append('<polygon points="'+' '.join(f'{xx},{yy}' for xx,yy in q)+f'" fill="{color(ink)}"/>')


def start(number, title, subtitle):
    svgs.clear()
    rect(0,0,W,H,'white','white',radius=0)
    text(40, 48, 'ICB-GUARD', 16, True, 'blue')
    text(40, 88, title, 33, True, serif=True)
    text(40, 119, subtitle, 17, ink='muted')
    text(1650, 48, f'FIGURE {number}', 14, True, 'muted')


def end(name, footer):
    text(40, 1172, footer, 14, ink='muted')
    (OUT / (name+'.svg')).write_text('<svg xmlns="http://www.w3.org/2000/svg" width="1800" height="1200" viewBox="0 0 1800 1200">\n'+ '\n'.join(svgs)+'\n</svg>', encoding='utf-8')
    pdf.showPage()


# Figure 1: system architecture.
start(1, 'Security architecture: trusted controls over agent-proposed actions',
      'Current implementation | Complete action binding, deterministic policy checks, single-action approval, and pre-execution revalidation')
rect(40,150,1720,235,'graybg','line',dash=True)
text(58,177,'TRUSTED CONTROL PLANE  /  roles use distinct credentials',16,True,'muted')
card(58,195,530,172,'A  Administrator / capability registry',
     'Register tool ID, actions, path roots, effects and parameters.\nSign capability; only the latest grant is active.\nIndependent operator file: deny actions / require parameter bounds. Default: no business bans.', 'blue')
card(608,195,560,172,'B  Trusted user channel / intent anchoring',
     'Intent LLM proposes symbolic rules and expected effects. Server owns the signed profile.\nNew input replaces policy and increments epoch; old tickets become stale. Taint persists.', 'blue')
card(1188,195,554,172,'C  Independent approver / operator setup',
     'Approve exact pending action only; never grant permanent rule expansion.\nStartup requires state outside the workspace, provisioned keys, mandatory checks, and no mock evidence.', 'teal')

rect(40,429,1720,517,'white','line',dash=True)
text(58,455,'RUNTIME AUTHORIZATION  /  serialized gateway mutations; one process / worker',16,True,'muted')
card(58,480,280,190,'1  Agent + adapter',
     'SDK / LangChain / BrowserGym / pi\nBind defaults; freeze complete JSON arguments.\nSubmit tool, action, session and capability ID.', 'blue',16)
card(58,692,280,184,'Input boundary',
     'Executor role required.\nStrict request schemas.\nServer session must exist.\nUnknown or failed responses stop execution.', 'blue',16)
card(378,480,390,198,'2  Evidence + provenance',
     'Allowlisted attached browser: live capture.\nA11y + OCR + optional Tesseract / grounding.\nFuse regions; optional time consistency.\nClient evidence cannot establish trust.', 'blue',16)
card(378,700,390,176,'3  Signed action evidence',
     'Bind full action hash, target/type, session, epoch and expiry.\nInclude sources, verifier versions, roles, region and crop hash.\nEd25519 signature.', 'blue',16)
card(808,480,516,263,'4  Policy engine + behavior alignment',
     'Hard checks: business rules, capability parameters, active grant, paths, deny rules, taint and evidence.\nIntent rules: exact tool match and finite sensitive-field constraints.\nBehavior: compare extracted effects against intent and capability restrictions.\nUncertainty escalates or blocks (Figure 2).', 'blue',17)
card(808,765,516,139,'5  Gateway decision controls',
     'Changed tool implementation: CONFIRM.\nApproval may override CONFIRM only; budget exhaustion becomes BLOCK.', 'amber',16)
card(1364,480,378,97,'BLOCK  /  deny', 'Stop; no execution ticket.', 'red',17)
card(1364,597,378,137,'CONFIRM  /  pending',
     'Independent approval issues one-use ticket. Re-authorize the identical action; repeat hard checks.', 'amber',17)
card(1364,754,378,122,'ALLOW  /  execution ticket',
     'Consume once before execution.\nRecheck policy, state and evidence; then invoke the trusted tool.', 'teal',17)
arrow([(338,552),(378,552)])
arrow([(573,678),(573,700)])
arrow([(768,791),(786,791),(786,566),(808,566)])
arrow([(1324,834),(1344,834),(1344,528),(1364,528)])
arrow([(1344,665),(1364,665)])
arrow([(1344,815),(1364,815)])
arrow([(1066,743),(1066,765)])
# Control dependencies cross only the intervening whitespace.
arrow([(323,367),(323,401),(924,401),(924,480)],'blue',True)
arrow([(888,367),(888,412),(1078,412),(1078,480)],'blue',True)
arrow([(1465,367),(1465,412),(1750,412),(1750,665),(1742,665)],'teal',True)
text(386,394,'capability',14,ink='blue')
text(1091,414,'rules + effects',14,ink='blue')
text(1366,918,'Approval + consumption protocol: Figure 3',15,ink='muted')

card(40,979,850,151,'Shared state and tamper-evident audit',
     'Session policy / epoch / effects / taint; pending, approval and execution tickets.\nDecision, approval and consumption records use a signed hash chain.\nRaw action bodies and screenshots are omitted from the default audit log.', 'teal',17)
card(910,979,850,151,'Explicit implementation boundary',
     'Gateway authorizes; it is not an OS sandbox. The executor and tool code are trusted.\nProduction blocks host shell / arbitrary process tools. GUI demo tools are previews.\nParameter bounds are enforced; implementation hashes are not runtime attestation.', 'amber',17)
end('icb_guard_architecture', 'Solid arrows: request / decision flow. Dashed arrows: trusted control inputs. Detailed ordering and conditional paths are expanded in Figures 2-3.')

# Figure 2: detailed checks, order, and evidence logic.
start(2, 'Policy semantics: hard boundaries, conditional evidence, and effect alignment',
      'Order follows policy.engine.evaluate() then policy.authorize.authorize_action(); P6 can hard-block a prior ALLOW or CONFIRM')

text(40,166,'(a)  ENGINE DECISION ORDER',19,True,'blue')
steps = [
 ('01  Independent business rules + capability bounds',
  'Operator deny/require rules run first; default empty. Enforce capability parameter bounds. Then require policy or valid rules, declared action and YAML capability requirements.'),
 ('02  File boundary + argument consistency',
  'Resolve absolute paths; enforce exact or directory grants. Empty envelope denies. Reject traversal / foreign paths / Windows alternate streams; reject conflicting target aliases.'),
 ('03  Explicit deny + direct sensitive reference',
  'Matching deny rule: BLOCK. A sink directly referencing a known high-risk object: BLOCK. These checks precede soft approval returns.'),
 ('04  Evidence certificate, when required / supplied',
  'Verify signature, signed vs outer fields, full action hash and expiry. Visual actions with unknown or conflicting evidence: BLOCK.'),
 ('05  Intent, finite parameter constraints + uncertainty',
  'No rules: sink / high-risk BLOCK, otherwise CONFIRM. Outside allow rule or insufficient sensitive constraints: CONFIRM. Derived taint / untrusted visual evidence: CONFIRM.'),
 ('06  Final engine checks',
  'Shell requires a non-dangerous command analysis, otherwise CONFIRM (production already blocks host shell). Remaining checks pass: engine ALLOW.'),
 ('07  Behavior alignment (P6), after engine',
  'Preserve engine BLOCK. With effect schema + profile, violations become BLOCK. Schema present but profile absent: downgrade engine ALLOW to CONFIRM.'),
]
for i,(title,body) in enumerate(steps):
    y=184+i*125
    card(40,y,833,109,title,body,'blue' if i<6 else 'teal',16)
    if i<6: arrow([(457,y+109),(457,y+125)],'blue')

text(913,166,'(b)  POLICY COMPONENTS',19,True,'blue')
card(913,184,847,170,'Symbolic least privilege',
     'Rules = {tool, allow / deny, predicate}; validated before matching.\nDSL: true, and/or/not, eq/ne, le/ge, in/not_in, glob, contains.\nSensitive values require positive finite eq/in constraints on every accepted branch. AND combines constrained fields; OR keeps only common fields.\nRaw parameter semantics are preserved: no blanket lowercase or URL decoding.', 'blue',16)
card(913,374,847,186,'Expected effects vs extracted effects',
     'Expected: intent targets, recipients, data types, max_items and forbidden effects; capability-denied effects are added to the forbidden set.\nActual: deterministic extraction from declared effect schema + action parameters.\nChecks: tool, scoped URL/path targets, recipients, data types, recipient-count limit and forbidden effects. Sensitive unknown effects: BLOCK.\nScope lists are conditional; max_items currently counts recipients, not all operations.', 'teal',16)
card(913,580,847,198,'Visual evidence path',
     'A11y has priority: matching perceptual evidence supports it; disagreement yields conflict. A structured source alone can establish trust.\nOtherwise: two agreeing source types establish trust; one is untrusted; none is unknown. Region agreement = intersection / smaller area (default 0.5).\nOptional previous capture: instability downgrades trust. Attached mode uses a fresh capture without previous-frame comparison.', 'blue',16)
card(913,798,847,155,'Two-level taint (P5)',
     'Sources: declared high-risk data / credentials. Sinks: network, sharing, persistence.\nScan nested object values and array elements: direct references BLOCK; other dirty sinks CONFIRM. Depth / size / unsupported-data failures BLOCK.\nMark source taint conservatively at ticket consumption; retain it across user turns.', 'teal',16)
card(913,973,847,135,'What these checks do not establish',
     'Provenance does not authorize a task. Intent alignment does not establish request safety. Extracted effects are not observed execution.\nTaint scans JSON values, not encoded content or object keys. Parameter bounds are per call, not cumulative budgets.', 'amber',15)
text(40,1101,'Hard BLOCK is never converted to ALLOW by approval.',20,True,'red')
end('icb_guard_policy_details', 'Conditional execution is explicit: optional verifier backends may be unavailable; effect alignment requires both a declared effect schema and an effect profile.')

# Figure 3: lifecycle, approval and enforcement boundary.
start(3, 'Authorization lifecycle: approval, one-time consumption, and state revocation',
      'ALLOW is permission to request execution consumption; the signed evidence certificate itself is not an execution token')
text(40,166,'(a)  SINGLE-ACTION APPROVAL AND EXECUTION',19,True,'blue')
card(40,187,400,185,'1  /authorize',
     'Executor submits full bound request.\nAll hard checks run.\nBLOCK: stop.\nALLOW: issue execution ticket.\nCONFIRM: create pending token.', 'blue',17)
card(480,187,400,185,'2  /confirm',
     'Independent approver accepts / rejects.\nPop pending token; verify expiry (300 s default), epoch and context hash.\nAccept: issue one-use approval ticket. Reject / stale: no grant.', 'amber',17)
card(920,187,400,185,'3  /authorize + approval ticket',
     'Pop approval ticket; verify identical session, tool and complete action.\nRe-run hard checks.\nOnly a resulting CONFIRM may be converted to ALLOW.', 'amber',17)
card(1360,187,400,185,'4  Execution ticket',
     'Server-held random token; 30 s TTL.\nBind action/tool/session, epoch, policy/taint/effects context hash, evidence hash and original request.', 'teal',17)
arrow([(440,279),(480,279)],'amber')
arrow([(880,279),(920,279)],'amber')
arrow([(1320,279),(1360,279)],'teal')
arrow([(240,372),(240,404),(1560,404),(1560,372)],'teal')
text(598,398,'Direct ALLOW skips human approval',16,ink='teal')

card(40,450,565,205,'5  /consume: pop first, then revalidate',
     'Executor role; serialized one-time ticket consumption.\nCheck TTL, epoch, context hash and complete binding.\nRe-authorize stored request with current capability / policy / taint and newly computed evidence.\nRequire ALLOW and unchanged evidence hash; otherwise refuse execution.', 'blue',17)
card(645,450,520,205,'6  State update + audit',
     'If tool is a high-risk source, mark session taint before returning success. Failed reads may over-taint.\nAppend signed consumption event.\nReplay of consumed ticket fails. SDK proceeds only after a successful response.', 'teal',17)
card(1205,450,555,205,'7  Trusted executor invokes tool',
     'Execute the frozen arguments checked by the gateway.\nExternal boundary: process/file/network permissions must prevent alternate access paths.\nNo atomic OS-level coupling to /consume; mutable resources still need executor-side protection.', 'amber',17)
arrow([(1760,307),(1780,307),(1780,431),(322,431),(322,450)],'teal')
arrow([(605,552),(645,552)],'blue')
arrow([(1165,552),(1205,552)],'teal')

text(40,704,'(b)  REVOCATION, AUDIT AND DEPLOYMENT GUARDS',19,True,'blue')
card(40,725,555,200,'Session / tool transitions',
     'New intent: increment epoch, replace rules, reset effects and confirmation budget; retain taint.\nClose session: clear policy, effects, taint and all tickets.\nNew registration invalidates old capability. Changed implementation converts an ALLOW to CONFIRM.', 'blue',17)
card(615,725,550,200,'Approval and resource bounds',
     'Default budget: 10 confirmations per epoch; exceeding it yields BLOCK.\nTicket maps: 10,000-entry guard each. Anchored sessions: 1,000-entry guard.\nBusiness policy: startup snapshot, audit hash, restart to reload. One worker.', 'blue',17)
card(1185,725,575,200,'Audit and credential separation',
     'Ed25519-signed hash chain for recorded decisions, approvals and consumption. Invalid chain stops append.\nFour distinct credentials (at least 32 characters). Agent must not hold privileged tokens. Protect gateway code, keys and state with OS permissions.', 'teal',17)

rect(40,941,1720,179,'amberbg','amber',dash=True)
text(58,972,'IMPLEMENTATION SCOPE / DO NOT INTERPRET AS ADDITIONAL ENFORCEMENT',18,True,'amber')
wrapped(58,1003,
        'Single trusted deployment domain; user/tenant-to-session authorization is not implemented. Host shell and declared arbitrary process execution are blocked in production.\n'
        'Capability implementation_hash is not a measurement of the executing binary. Parameter constraints enforce a documented subset: types, values, bounds, nested fields and array items.\n'
        'Hash chains need external checkpoints to detect suffix deletion. Derived taint may be approved; no complete cross-session or transformed-content lineage is claimed.\n'
        'pi browser/click/type demo tools are authorization previews. R-Judge policy-assisted judgment is an evaluation path, not part of the runtime authorization chain.',
        1684,16,25)
end('icb_guard_ticket_lifecycle', 'Based on the current repository implementation. All numeric limits shown are defaults; deployment configuration may change configurable limits.')
pdf.save()
if overflows:
    raise RuntimeError(f'Text overflow: {overflows}')
print('Created vector PDF (3 pages) and 3 editable SVG diagrams in', OUT)
