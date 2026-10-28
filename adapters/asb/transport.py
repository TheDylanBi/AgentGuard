"""Bounded response-only recovery with credential-free, per-request diagnostics."""
import copy
import json
import time
import types
from attestation.hashing import object_hash


class ActionTransportError(RuntimeError):
    def __init__(self, code, **diagnostic):
        self.diagnostic = {'stage': 'action_model', 'code': code, **diagnostic}
        super().__init__('ASB action model: ' + code)


class ActionTransport:
    def __init__(self, config, deadline, session=None):
        import requests
        self.config, self.deadline = config, deadline
        self.session = session or requests.Session()
        self.requests = 0
        self.records = []

    def __call__(self, query, temperature=0.0):
        retry_code = None
        started = time.time()
        for attempt in range(self.config.get('response_retries', 0) + 1):
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or self.requests >= self.config['max_requests']:
                raise ActionTransportError('request_budget_exhausted', request_count=self.requests)
            self.requests += 1
            record = {'request': self.requests, 'attempt': attempt + 1,
                'query_kind': 'planning' if getattr(query, 'message_return_type', None) == 'json' else 'action',
                'sent_max_tokens': self.config['max_tokens'], 'status': 'pending'}
            self.records.append(record)
            body = {'model': self.config['model'], 'messages': copy.deepcopy(query.messages),
                self.config.get('max_tokens_field', 'max_tokens'): self.config['max_tokens'],
                'temperature': temperature, 'seed': 0}
            if retry_code:
                body['messages'].insert(0, {'role': 'system', 'content':
                    'The preceding response was unusable (' + retry_code + '). Regenerate the SAME request '
                    'concisely within the output budget. Return complete JSON if requested; otherwise a '
                    'concise answer or complete native tool calls. Do not invent missing facts or permission. '
                    'No proposed call from that failed response was executed.'})
            if query.tools:
                tools = copy.deepcopy(query.tools)
                if self.config['tool_schema'] == 'empty-object':
                    for tool in tools:
                        if tool['function'].get('parameters') is None:
                            tool['function']['parameters'] = {'type': 'object', 'properties': {}, 'additionalProperties': False}
                body['tools'] = tools
            tick = time.monotonic()
            try:
                try:
                    response = self.session.post(self.config['base_url'].rstrip('/') + '/chat/completions',
                        headers={'Authorization': 'Bearer ' + self.config['api_key'], 'Content-Type': 'application/json',
                                 **self.config.get('headers', {})},
                        json=body, timeout=(min(15, remaining), min(60, remaining)), allow_redirects=False)
                    record['http_status'] = response.status_code
                    if response.status_code != 200:
                        raise ActionTransportError('http_status', http_status=response.status_code)
                    try:
                        value = response.json()
                    except (ValueError, TypeError):
                        raise ActionTransportError('invalid_response_json', http_status=200) from None
                except ActionTransportError:
                    raise
                except Exception as error:
                    raise ActionTransportError('transport', error_type=type(error).__name__) from None
                if time.monotonic() >= self.deadline:
                    raise ActionTransportError('task_deadline')
                if not isinstance(value, dict) or not isinstance(value.get('choices'), list) or not value['choices']:
                    raise ActionTransportError('missing_choices')
                choice = value['choices'][0]
                if not isinstance(choice, dict):
                    raise ActionTransportError('invalid_choice')
                finish = choice.get('finish_reason')
                if finish is not None and not isinstance(finish, str):
                    raise ActionTransportError('invalid_finish_reason')
                record['finish_reason'] = finish if finish in {'stop','tool_calls','length','content_filter',None} else 'other'
                usage = value.get('usage', {})
                record['usage'] = {k:v for k,v in usage.items() if k in {'prompt_tokens','completion_tokens','total_tokens'}
                                   and type(v) is int and v >= 0} if isinstance(usage, dict) else {}
                if finish == 'length':
                    raise ActionTransportError('truncated_output', finish_reason='length', usage=record['usage'])
                if finish == 'content_filter':
                    raise ActionTransportError('model_content_filter')
                message = choice.get('message')
                if not isinstance(message, dict):
                    raise ActionTransportError('invalid_message')
                content = message.get('content')
                refusal = message.get('refusal')
                if isinstance(refusal, str) and refusal and not content and not message.get('tool_calls'):
                    # A valid provider refusal is an answer, never a malformed
                    # response to regenerate in search of compliance.
                    content = refusal
                    record['model_refusal'] = True
                if content is not None and not isinstance(content, str):
                    raise ActionTransportError('invalid_content')
                calls = message.get('tool_calls') or []
                if not isinstance(calls, list):
                    raise ActionTransportError('invalid_tool_calls')
                parsed = []
                for call in calls:
                    fn = call.get('function') if isinstance(call, dict) else None
                    if not isinstance(fn, dict) or not isinstance(fn.get('name'), str) or not fn['name']:
                        raise ActionTransportError('invalid_tool_call')
                    params = fn.get('arguments', '{}')
                    try:
                        params = json.loads(params) if isinstance(params, str) else params
                    except (ValueError, TypeError):
                        raise ActionTransportError('invalid_tool_arguments_json') from None
                    parsed.append({'name': fn['name'], 'parameters': params})
                if not parsed and not content:
                    raise ActionTransportError('empty_response')
                record.update(status='complete', response_chars=len(content or ''),
                              response_hash=object_hash(message), tool_call_count=len(parsed))
                finished = time.time()
                return types.SimpleNamespace(response_message=content, tool_calls=parsed or None), [started], [finished], [0.0], [finished-started]
            except ActionTransportError as error:
                record.update(status='error', diagnostic=copy.deepcopy(error.diagnostic))
                # Regenerate only unusable responses before any dispatch. Never
                # retry a valid refusal/empty tool choice or a security decision.
                recoverable = error.diagnostic['code'] in {
                    'truncated_output','missing_choices','invalid_choice','invalid_finish_reason','invalid_response_json',
                    'invalid_message','invalid_content','invalid_tool_calls','invalid_tool_call',
                    'invalid_tool_arguments_json','empty_response'}
                if attempt < self.config.get('response_retries', 0) and recoverable:
                    retry_code = error.diagnostic['code']
                    continue
                raise
            finally:
                record['elapsed_seconds'] = round(time.monotonic()-tick, 4)
