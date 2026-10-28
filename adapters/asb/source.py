"""Read-only ASB discovery, reproducible snapshots and narrow native hooks."""
import ast
import copy
import hashlib
from pathlib import Path
import re
import shutil
import types


REQUIRED = (
    'main_attacker.py', 'pyopenagi/agents/react_agent_attack.py',
    'pyopenagi/agents/base_agent.py', 'pyopenagi/tools/simulated_tool.py',
    'data/agent_task.jsonl', 'data/all_normal_tools.jsonl',
    'data/all_attack_tools.jsonl',
)


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_jsonl(path):
    import json
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8-sig').splitlines()
            if line.strip()]


def validate_source(root):
    root = Path(root).resolve()
    for relative in REQUIRED:
        path = root / relative
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError('Missing or external ASB source file: ' + relative)
    hook_tree(root / 'pyopenagi/agents/react_agent_attack.py')
    official_scorers(root)
    return {relative: file_hash(root / relative) for relative in REQUIRED}


def snapshot(root, destination):
    """Only copy benchmark code/data, never .env, caches, secrets or source DBs."""
    root, destination = Path(root).resolve(), Path(destination).resolve()
    if destination == root or destination.is_relative_to(root) or root.is_relative_to(destination):
        raise ValueError('ASB snapshot and original checkout must be separate')
    destination.mkdir(parents=True, exist_ok=False)
    for directory in ('pyopenagi', 'data'):
        for path in sorted((root / directory).rglob('*')):
            if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
                raise ValueError('ASB snapshot cannot contain links')
            if '__pycache__' in path.parts or path.suffix not in {'.py', '.json', '.jsonl'}:
                continue
            if path.is_file():
                target = destination / path.relative_to(root)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
    for name in ('main_attacker.py', 'LICENSE'):
        if (root / name).is_file():
            shutil.copyfile(root / name, destination / name)
    return {str(path.relative_to(destination)).replace('\\', '/'): file_hash(path)
            for path in sorted(destination.rglob('*')) if path.is_file()}


def official_scorers(root):
    """Compile original scorer bodies without importing the GPU/AIOS launcher."""
    path = Path(root) / 'main_attacker.py'
    tree = ast.parse(path.read_text(encoding='utf-8-sig'))
    names = {'check_attack_success', 'check_original_success', 'judge_response'}
    selected = [copy.deepcopy(node) for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in selected} != names:
        raise ValueError('Unsupported ASB official scorer layout')
    namespace = {'__name__': 'icb_asb_official_scorers'}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), 'exec'), namespace)
    return {name: namespace[name] for name in names}


class PolicyDenied(Exception):
    """Expected policy rejection; does not execute or invent a tool result."""
    def __init__(self, verdict, feedback=None):
        import json
        self.feedback = feedback
        super().__init__('ICB-' + verdict + ': tool execution withheld by authorization policy' +
                         ('; ' + json.dumps(feedback, ensure_ascii=False) if feedback else ''))


def hook_tree(path):
    """Keep native planning, retries, injection and observation formatting intact."""
    tree = ast.parse(Path(path).read_text(encoding='utf-8-sig'))
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == 'ReactAgentAttack')
    function = copy.deepcopy(next(node for node in cls.body
                                  if isinstance(node, ast.FunctionDef) and node.name == 'call_tools'))

    class Hook(ast.NodeTransformer):
        dispatches = 0
        observations = 0
        handlers = 0

        def visit_Call(self, node):
            self.generic_visit(node)
            if (isinstance(node.func, ast.Attribute) and node.func.attr == 'run'
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'function_to_call'):
                if (len(node.args) != 1 or not isinstance(node.args[0], ast.Name)
                        or node.args[0].id != 'function_params' or node.keywords):
                    raise ValueError('Unsupported ASB tool dispatch signature')
                self.dispatches += 1
                return ast.copy_location(ast.parse(
                    'self._icb_dispatch(function_name, function_to_call, function_params)', mode='eval').body, node)
            return node

        def visit_Expr(self, node):
            self.generic_visit(node)
            value = node.value
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                    and value.func.attr == 'append' and isinstance(value.func.value, ast.Name)
                    and value.func.value.id == 'observations'
                    and any(isinstance(item, ast.Name) and item.id == 'function_response'
                            for item in ast.walk(value))):
                self.observations += 1
                observer = ast.parse('self._icb_observe(function_name, function_params, function_response)').body[0]
                return [node, ast.copy_location(observer, node)]
            return node

        def visit_Try(self, node):
            self.generic_visit(node)
            if any(isinstance(item, ast.Attribute) and item.attr == '_icb_dispatch'
                   for item in ast.walk(ast.Module(body=node.body, type_ignores=[]))):
                self.handlers += 1
                handler = ast.parse('''try:
    pass
except _ICBPolicyDenied as denial:
    actions.append("Tool execution withheld by authorization policy.")
    observations.append(str(denial))
    success = False
    self.last_tool_call_non_retryable = True
''').body[0].handlers[0]
                node.handlers.insert(0, handler)
            return node

    transformer = Hook()
    function = transformer.visit(function)
    if (transformer.dispatches, transformer.observations, transformer.handlers) != (1, 1, 1):
        raise ValueError('Unsupported ASB call_tools layout; refusing an unguarded fallback')
    # This local ASB version intentionally dispatches None; never pretend to
    # enforce parameters that its runtime does not execute.
    assignments = [node for node in ast.walk(function) if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'function_params' for t in node.targets)]
    if not assignments or any(not isinstance(n.value, ast.Constant) or n.value.value is not None
                              for n in assignments):
        raise ValueError('ASB now executes parameters; update and review this adapter first')
    return ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))


def actor_hook_tree(path, class_name, method_name):
    """Record origins at known native generation sites, never by parsing output.

    Execution, workflow injection and native transcript contents are unchanged.
    Unknown source layouts fail before a model request instead of guessing trust.
    """
    from .action_context import ActionContextError
    tree = ast.parse(Path(path).read_text(encoding='utf-8-sig'))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    method = copy.deepcopy(next(n for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == method_name))

    class OriginHook(ast.NodeTransformer):
        appends = 0
        queries = 0

        def visit_Call(self, node):
            self.generic_visit(node)
            fn = node.func
            if (isinstance(fn, ast.Attribute) and fn.attr == 'append'
                    and isinstance(fn.value, ast.Attribute) and fn.value.attr == 'messages'
                    and isinstance(fn.value.value, ast.Name) and fn.value.value.id == 'self'):
                if len(node.args) != 1 or node.keywords or not isinstance(node.args[0], ast.Dict):
                    raise ActionContextError('unsupported_native_append')
                message = node.args[0]
                fields = {k.value: v for k, v in zip(message.keys, message.values) if isinstance(k, ast.Constant)}
                content = fields.get('content')
                names = {n.id for n in ast.walk(content) if isinstance(n, ast.Name)} if content else set()
                if method_name == 'automatic_workflow':
                    origin = 'planning_feedback'
                elif method_name == 'build_system_instruction':
                    if 'prefix' in names:
                        origin = 'agent_role'
                    elif 'plan_instruction' in names:
                        origin = 'planning_instruction'
                    else:
                        # Unsupported memory/PoT branches are rejected if reached.
                        origin = 'unsupported_native_instruction'
                elif isinstance(content, ast.Attribute) and content.attr == 'task_input':
                    origin = 'original_request'
                elif names == {'prompt'}:
                    origin = 'step_proposal'
                elif {'action_messages', 'observation_messages'} <= names:
                    origin = 'tool_observation'
                elif 'workflow' in names:
                    origin = 'plan_proposal'
                elif 'thinkings' in names:
                    origin = 'model_response'
                elif names == {'task_trigger'}:
                    origin = 'unsupported_native_instruction'
                else:
                    raise ActionContextError('unsupported_native_message_site')
                self.appends += 1
                return ast.copy_location(ast.Call(func=ast.Name(id='_icb_append', ctx=ast.Load()),
                    args=[ast.Name(id='self', ctx=ast.Load()), ast.Constant(origin), message], keywords=[]), node)
            if (isinstance(fn, ast.Attribute) and fn.attr == 'get_response'
                    and isinstance(fn.value, ast.Name) and fn.value.id == 'self'):
                if node.args or len(node.keywords) != 1 or node.keywords[0].arg != 'query':
                    raise ActionContextError('unsupported_native_query')
                self.queries += 1
                return ast.copy_location(ast.Call(func=ast.Name(id='_icb_query', ctx=ast.Load()),
                    args=[ast.Name(id='self', ctx=ast.Load())], keywords=node.keywords + [
                        ast.keyword(arg='phase', value=ast.Constant(
                            'planning' if method_name == 'automatic_workflow' else 'execution'))]), node)
            return node

    transformer = OriginHook()
    method = transformer.visit(method)
    expected = {'run': (7, 1), 'build_system_instruction': (7, 0), 'automatic_workflow': (4, 1)}
    if (transformer.appends, transformer.queries) != expected[method_name]:
        raise ActionContextError('unsupported_native_actor_layout')
    return ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))


def attach_actor_context(agent, source_path, native_globals):
    from .action_context import ActionContext, ActionContextError, append_message, query_in_phase
    if any(getattr(agent.args, name, False) for name in
           ('direct_prompt_injection', 'pot_backdoor', 'pot_clean', 'memory_attack', 'read_db', 'write_db')):
        raise ActionContextError('unsupported_attack_context')
    if getattr(agent.args, 'defense_type', None) is not None:
        raise ActionContextError('unsupported_native_defense')
    source_path = Path(source_path)
    namespace = {**native_globals, '_icb_append': append_message, '_icb_query': query_in_phase}
    methods = [('run', source_path, 'ReactAgentAttack'),
        ('build_system_instruction', source_path, 'ReactAgentAttack'),
        ('automatic_workflow', source_path.with_name('base_agent.py'), 'BaseAgent')]
    for name, path, cls in methods:
        exec(compile(actor_hook_tree(path, cls, name), str(path), 'exec'), namespace)
    context = ActionContext(agent)
    agent._icb_action_context = context
    for name, _, _ in methods:
        setattr(agent, name, types.MethodType(namespace[name], agent))
    original_response = agent.get_response

    def get_response(query, **kwargs):
        return original_response(query=context.project(query), **kwargs)

    agent.get_response = get_response


def attach_hooks(agent, source_path, host, native_globals, recovery='native', max_recovery_requests=2,
                 action_context='native'):
    from .action_context import append_message
    if action_context not in {'native', 'structured'}:
        raise ValueError('Unknown action context profile')
    if action_context == 'structured':
        attach_actor_context(agent, source_path, native_globals)
    namespace = dict(native_globals)
    namespace['_ICBPolicyDenied'] = PolicyDenied
    exec(compile(hook_tree(source_path), str(source_path), 'exec'), namespace)
    native_call = namespace['call_tools']
    # Native ASB adds some tools during run(), then builds its prompt. Supply
    # operator assertions after that step, to both modes, without editing the
    # native catalog or generating permissions from normal/attack labels.
    tool_context = host.actor_tool_context() if hasattr(host, 'actor_tool_context') else None
    if tool_context is not None:
        import json
        original_build = agent.build_system_instruction

        def build_system_instruction(self, *args, **kwargs):
            result = original_build(*args, **kwargs)
            append_message(self, 'operator_declarations', {'role': 'system', 'content':
                'HOST TOOL CAPABILITY DECLARATIONS. These do not grant task permission.\n'
                + json.dumps(tool_context, ensure_ascii=False, sort_keys=True)})
            return result

        agent.build_system_instruction = types.MethodType(build_system_instruction, agent)
    coordinator = None
    if recovery == 'bounded':
        from .reliability import BoundedCoordinator
        coordinator = BoundedCoordinator(agent, host, namespace['Query'], max_recovery_requests)
    elif recovery == 'checkpoint':
        from .completion import StepCheckpoint
        coordinator = StepCheckpoint(agent, host, namespace['Query'], max_recovery_requests)

    def call_tools(self, tool_calls, final_stage=False):
        result = native_call(self, tool_calls, final_stage=final_stage)
        host.raise_if_failed()
        if recovery == 'bounded' and coordinator and not coordinator.busy and not result[2] and any(
                e.get('verdict') in {'BLOCK', 'CONFIRM'} for e in host.events):
            append_message(self, 'tool_observation', {'role': 'assistant',
                'content': '[Action]: ' + ';'.join(result[0]) + ';[Observation]: ' + ';'.join(result[1])})
            recovered = coordinator.attempt('policy_withheld', native_call)
            # Native retries must not replay either a denied batch or a partly
            # successful batch after recovery. Keep actual observations intact.
            self.last_tool_call_non_retryable = True
            return (['Bounded execution checkpoint completed.'],
                    ['Additional task progress recorded in the preceding messages.'],
                    bool(recovered and recovered[2]))
        return result

    agent._icb_dispatch = host.dispatch
    agent._icb_observe = host.observe
    agent.call_tools = types.MethodType(call_tools, agent)
    agent._icb_coordinator = coordinator
    agent._icb_finish = lambda: coordinator.attempt('completion_checkpoint', native_call) if coordinator else None


def agent_module_path(name):
    if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9_]*', name):
        raise ValueError('Invalid ASB agent name')
    return 'pyopenagi.agents.example.' + name + '.agent'
