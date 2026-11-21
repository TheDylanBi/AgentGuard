# ICB-Guard connection to the official AgentHarm eval

This is an Inspect **approver extension**, not an AgentHarm runner or benchmark
adapter. It leaves the official `inspect_evals/agentharm` task, agent loop,
tools, scorers, dataset loading, concurrency, and `.eval` logs unchanged. The
only integration point is Inspect's official pre-execution `--approval` hook.

Install the project-local extension once:

```powershell
& '.\.venv\Scripts\python.exe' -X utf8 -m pip install -e `
    '.\integrations\inspect_icb_guard'
```

The guarded run requires the same independent review model as AgentDojo review:

```powershell
$env:ICB_INTENT_LLM_BASE_URL = '<intent-model-openai-compatible-base-url>'
$env:ICB_INTENT_LLM_API_KEY = '<intent-model-api-key>'
$env:ICB_INTENT_LLM_MODEL = '<intent-model-id>'
$env:ICB_INTENT_LLM_TIMEOUT_SECONDS = '120'
$env:ICB_INTENT_LLM_MAX_TOKENS = '4096'
$env:ICB_INTENT_LLM_OUTPUT_FORMAT = 'text'
```

The action model and judge model continue to use Inspect's official model
configuration. For an OpenAI-compatible endpoint, use Inspect's documented
provider convention (the `qwen` provider label is local and can be renamed):

```powershell
$env:PYTHONUTF8 = '1'
$env:QWEN_BASE_URL = '<action-model-openai-compatible-base-url>'
$env:QWEN_API_KEY = '<action-model-api-key>'
$actionModel = 'openai-api/qwen/<action-model-id>'

# AgentHarm's official default scorers use GPT-4o.
$env:OPENAI_API_KEY = '<official-judge-api-key>'
```

Run the harmful task exactly as documented by AgentHarm:

```powershell
& '.\.venv\Scripts\inspect.exe' eval inspect_evals/agentharm `
    --model $actionModel `
    --approval '.\config\inspect\icb_guard_agentharm_review.yaml'
```

Run the benign utility task with the same guard:

```powershell
& '.\.venv\Scripts\inspect.exe' eval inspect_evals/agentharm_benign `
    --model $actionModel `
    --approval '.\config\inspect\icb_guard_agentharm_review.yaml'
```

The official tutorial also supports running both tasks together. A guarded
validation smoke run is:

```powershell
& '.\.venv\Scripts\inspect.exe' eval-set `
    inspect_evals/agentharm inspect_evals/agentharm_benign `
    --model $actionModel `
    --approval '.\config\inspect\icb_guard_agentharm_review.yaml' `
    -T split=val --limit 2 --max-samples 1 `
    --log-dir '.\logs\agentharm_guarded_smoke'
```

For the matched baseline, use the identical official command and omit only
`--approval` (and write to a different log directory). For the public run,
change `split=val` to `split=test_public` and remove `--limit`. Use
`-T refusal_judge=...` and `-T semantic_judge=...` only when intentionally
choosing a non-default judge model; that is a protocol deviation to report.

Decision mapping at the execution boundary:

* `allow` -> Inspect `approve` -> official tool executes
* `deny` -> Inspect `reject` -> official tool does not execute
* `needs_evidence` -> Inspect `reject`, recorded as `CONFIRM`

Review transport/schema failures propagate as sample errors; they are not
converted into successful defenses. Approval decisions and ICB metadata are
written into the official Inspect `.eval` transcript.
