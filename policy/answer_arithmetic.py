"""Bounded arithmetic checks on an actor's answer, never task authorization.

No tools or Python expressions are executed. Only literal Decimal arithmetic is
accepted. Table sums verify addition, not inclusion criteria, units in real life,
correct source selection, or fulfillment of a natural-language task.
"""
import ast
from decimal import Decimal, DecimalException, localcontext
import re

MAX_TEXT=32_000
NUM=r'[-+]?(?:\d+(?:\.\d+)?|\.\d+)'


def calculate(expression):
    if not isinstance(expression,str) or not 1<=len(expression)<=512:
        raise ValueError('arithmetic_input_limit')
    expression=expression.replace('×','*').replace('÷','/').replace('−','-')
    if not re.fullmatch(r'[\d\s.+*/()%\-]+',expression):
        raise ValueError('literal_arithmetic_only')
    nesting=0
    for char in expression:
        if char=='(':nesting+=1
        elif char==')':nesting-=1
        if nesting>12 or nesting<0:raise ValueError('arithmetic_complexity_limit')
    expression=re.sub(r'(\d+(?:\.\d+)?)\s*%',r'(\1/100)',expression).strip()
    try:
        tree=ast.parse(expression,mode='eval');count=0
        def visit(node,depth=0):
            nonlocal count
            count+=1
            if count>96 or depth>12:raise ValueError('arithmetic_complexity_limit')
            if isinstance(node,ast.Constant) and type(node.value) in (int,float):
                segment=ast.get_source_segment(expression,node)
                if not segment or not re.fullmatch(NUM,segment):raise ValueError('invalid_literal')
                result=Decimal(segment)
            elif isinstance(node,ast.UnaryOp) and isinstance(node.op,(ast.UAdd,ast.USub)):
                result=visit(node.operand,depth+1)
                if isinstance(node.op,ast.USub):result=-result
            elif isinstance(node,ast.BinOp) and isinstance(node.op,(ast.Add,ast.Sub,ast.Mult,ast.Div)):
                left,right=visit(node.left,depth+1),visit(node.right,depth+1)
                if isinstance(node.op,ast.Add):result=left+right
                elif isinstance(node.op,ast.Sub):result=left-right
                elif isinstance(node.op,ast.Mult):result=left*right
                else:result=left/right
            else:raise ValueError('unsupported_arithmetic')
            if not result.is_finite() or abs(result)>Decimal('1e15') or abs(result.as_tuple().exponent)>48:
                raise ValueError('arithmetic_value_limit')
            return result
        with localcontext() as context:
            context.prec=40
            return visit(tree.body)
    except (SyntaxError,DecimalException,RecursionError,OverflowError) as error:
        raise ValueError('invalid_arithmetic') from None


def scalar(cell):
    text=re.sub(r'\*\*|`','',cell).strip()
    match=re.fullmatch(r'([€$£¥]?)\s*('+NUM+r'|[-+]?\d{1,3}(?:,\d{3})+(?:\.\d+)?)\s*([€$£¥]?)',text)
    if not match or match[1] and match[3]:raise ValueError('not_a_scalar')
    value=Decimal(match[2].replace(',',''))
    if abs(value)>Decimal('1e15') or abs(value.as_tuple().exponent)>24:
        raise ValueError('scalar_limit')
    return value,match[1] or match[3]


def check_answer(text):
    if not isinstance(text,str) or len(text)>MAX_TEXT:
        return {'status':'input_limit','checks':[], 'authority':False}
    checks=[]
    # Deliberately accept only an entire literal expression on the left. Names,
    # dates, code, units and prose cannot become arithmetic inputs by stripping.
    for line in text.splitlines():
        plain=re.sub(r'\*\*|`','',line).strip()
        if plain.count('=')!=1:continue
        left,right=plain.split('=')
        if not re.search(r'[+*/×÷%]|\s-\s',left):continue
        try:
            expected=calculate(left.strip());claimed,unit=scalar(right.strip())
        except (ValueError,DecimalException):continue
        with localcontext() as context:
            context.prec=48
            merely_rounded=expected!=claimed and expected.quantize(Decimal(1).scaleb(claimed.as_tuple().exponent))==claimed
        checks.append({'kind':'literal_equation','expression':left.strip(), 'claimed':str(claimed),
            'computed':str(expected),'consistent':None if merely_rounded else expected==claimed,
            'rounding_contract_required':merely_rounded,
            'scope':'literal_arithmetic_only','unit_inferred':False})
        if len(checks)>=16:break
    blocks=[];block=[]
    for line in text.splitlines()+['']:
        if line.strip().startswith('|') and line.strip().endswith('|'):block.append(line)
        elif block:blocks.append(block);block=[]
    for block in blocks[:8]:
        rows=[[part.strip() for part in line.strip().strip('|').split('|')] for line in block]
        width=len(rows[0])
        if len(rows)<5 or not 2<=width<=6 or any(len(row)!=width for row in rows):continue
        if width==2:column=1
        else:
            columns=[i for i,name in enumerate(rows[0]) if re.fullmatch(
                r'(amount|cost|price|金额|费用|支出)(?:\s*\([^|]{1,16}\))?',
                re.sub(r'\*','',name).strip().lower())]
            if len(columns)!=1:continue
            column=columns[0]
        totals=[i for i,row in enumerate(rows) if re.sub(r'\*','',next((cell for j,cell in enumerate(row) if j!=column and cell), '')).strip().lower()
                in {'total','grand total','subtotal','总计','合计','总额'}]
        if totals!=[len(rows)-1]:continue
        if not all(re.fullmatch(r':?-+:?',cell.replace(' ','')) for cell in rows[1]):continue
        try:
            values=[scalar(row[column]) for row in rows[2:]]
        except (ValueError,DecimalException):continue
        if len({unit for _,unit in values})!=1:continue
        # Decimal addition uses a local bound; reject huge inputs before summing.
        if any(abs(value)>Decimal('1e15') or abs(value.as_tuple().exponent)>24 for value,_ in values):continue
        with localcontext() as context:
            context.prec=40
            expected=sum((value for value,_ in values[:-1]),Decimal(0))
        checks.append({'kind':'table_column_sum', 'column':column,'claimed':str(values[-1][0]),
            'computed':str(expected),'consistent':expected==values[-1][0],
            'scope':'addition_only_not_row_selection','unit_inferred':False})
        if len(checks)>=24:break
    return {'status':'checked' if checks else 'no_supported_claims', 'checks':checks,
            'authority':False,'task_complete':None,
            'note':'Verify arithmetic only. Source truth, interpretation and task authorization remain independent.'}
