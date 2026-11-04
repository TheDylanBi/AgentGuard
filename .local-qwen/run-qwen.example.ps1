param(
    [ValidateSet('guarded', 'baseline')][string]$Mode = 'guarded',
    [string]$UserTask = 'user_task_0',
    [switch]$AllTasks,
    [switch]$AllSuites,
    [ValidateSet('full','no-semantic-review','no-hard-gate')][string]$Ablation = 'full',
    [string]$Output = '',
    [ValidateSet('workspace','travel','banking','slack')][string]$Suite = 'workspace',
    [string]$Attack = '',
    [string]$InjectionTask = '',
    [switch]$ContinueOnError,
    [switch]$StopOnError,
    [switch]$ReadPreflight,
    [ValidateSet('rules', 'boundary', 'review')][string]$IntentFormat = 'rules',
    [ValidateSet('legacy', 'scoped')][string]$ReviewCoordination = 'scoped',
    [string]$CalendarReminderWindow = '09:00-10:00',
    [string]$TrustedCurrentDay = '',
    [string]$TrustedCurrentTime = '',
    [ValidateSet('explicit','run-day')][string]$PaymentDatePolicy = 'run-day',
    [ValidateSet('explicit','two-party')][string]$EqualSharePolicy = 'two-party',
    [ValidateSet('inherit','enabled','disabled')][string]$ReviewThinkingMode = 'disabled',
    [ValidateRange(2,120)][double]$ReviewCallTimeout = 45,
    [ValidateRange(0,120)][double]$ReviewActionReserve = 15,
    [switch]$CompactIntentJson,
    [ValidateRange(256,8192)][int]$ActionMaxTokens = 2048,
    [switch]$Check,
    [string]$AuthorizationContracts = ''
)
$ErrorActionPreference = 'Stop'
$env:ICB_REVIEW_CALL_TIMEOUT_SECONDS = $ReviewCallTimeout.ToString([Globalization.CultureInfo]::InvariantCulture)
$env:ICB_REVIEW_ACTION_RESERVE_SECONDS = $ReviewActionReserve.ToString([Globalization.CultureInfo]::InvariantCulture)
if ($ReviewThinkingMode -ne 'inherit') {
    Remove-Item Env:ICB_REVIEW_ENABLE_THINKING -ErrorAction SilentlyContinue
    Remove-Item Env:ICB_REVIEW_RETRY_ENABLE_THINKING -ErrorAction SilentlyContinue
    $env:ICB_REVIEW_THINKING_MODE = $ReviewThinkingMode
    $env:ICB_REVIEW_RETRY_THINKING_MODE = $ReviewThinkingMode
    if ($ReviewThinkingMode -eq 'disabled') {
        Remove-Item Env:ICB_REVIEW_REASONING_EFFORT -ErrorAction SilentlyContinue
        Remove-Item Env:ICB_REVIEW_RETRY_REASONING_EFFORT -ErrorAction SilentlyContinue
    }
}
# $baseUrl = 'http://10.16.82.231:8000/v1'
# $modelId = 'Qwen/Qwen3-8B'
# # Server currently has no authentication; this is a placeholder, not a secret.
# $apiKey = 'local-no-auth'
$baseUrl = $env:ICB_ACTION_BASE_URL
$modelId = $env:ICB_ACTION_MODEL
$apiKey = $env:ICB_ACTION_API_KEY
# $env:ICB_INTENT_LLM_BASE_URL = $baseUrl
# $env:ICB_INTENT_LLM_API_KEY = $apiKey
# $env:ICB_INTENT_LLM_MODEL = $modelId
# $env:ICB_INTENT_LLM_TIMEOUT_SECONDS = '120'
# # vLLM 0.8.5: constrain final intent JSON and keep reasoning out of the envelope.
# $env:ICB_INTENT_LLM_OUTPUT_FORMAT = 'vllm_guided_json'
# $env:ICB_INTENT_LLM_ENABLE_THINKING = 'false'
# $env:ICB_INTENT_LLM_COMPACT_JSON = $CompactIntentJson.IsPresent.ToString().ToLowerInvariant()
# $env:ICB_INTENT_LLM_MAX_TOKENS = '4096'
# 独立意图模型：填写服务商实际提供的地址和模型 ID
# Configure ICB_INTENT_LLM_BASE_URL in the calling environment.
# Configure ICB_INTENT_LLM_API_KEY in the calling environment.
# Configure ICB_INTENT_LLM_MODEL in the calling environment.
$env:ICB_INTENT_LLM_TIMEOUT_SECONDS = '120'
$env:ICB_INTENT_LLM_MAX_TOKENS = '4096'
# 通用模式：仍由项目提示词要求 JSON，并由程序严格校验
$env:ICB_INTENT_LLM_OUTPUT_FORMAT = 'text'
$env:ICB_INTENT_LLM_COMPACT_JSON = 'false'
# 移除原来针对本地 Qwen 的扩展参数
Remove-Item Env:ICB_INTENT_LLM_ENABLE_THINKING -ErrorAction SilentlyContinue

# $models = Invoke-RestMethod -Uri "$baseUrl/models" -TimeoutSec 15
# $remote = @($models.data | Where-Object { $_.id -eq $modelId })
# if ($remote.Count -ne 1) { throw 'Expected Qwen model is not served.' }
# $contextLength = [int]$remote[0].max_model_len
# if ($contextLength -le 0) { throw 'Server did not report max_model_len.' }
# $config = @{ providers = @{ 'local-qwen' = @{
#     baseUrl = $baseUrl; api = 'openai-completions'; apiKey = $apiKey
#     # Capability metadata must be true for pi to send enable_thinking=false
#     # when the session selects thinkingLevel=off.
#     models = @(@{ id = $modelId; name = 'Local Qwen3-8B'; reasoning = $true
#         input = @('text'); contextWindow = $contextLength; maxTokens = $ActionMaxTokens
#         cost = @{ input = 0; output = 0; cacheRead = 0; cacheWrite = 0 }
#         compat = @{ supportsStore = $false; supportsDeveloperRole = $false
#             supportsReasoningEffort = $false; maxTokensField = 'max_tokens'
#             thinkingFormat = 'qwen-chat-template' }
#     })
# } } }
# 使用明确的客户端上下文上限，不依赖本地 vLLM 的 max_model_len 字段。
# 这里先采用 32768；它不是服务商模型的最大上下文长度。
$contextLength = 32768

$config = @{
    providers = @{
        'remote-action' = @{
            baseUrl = $baseUrl
            api = 'openai-completions'
            apiKey = $apiKey
            models = @(
                @{
                    id = $modelId
                    name = 'Remote DeepSeek Action Model'
                    reasoning = $true
                    input = @('text')
                    contextWindow = $contextLength
                    maxTokens = $ActionMaxTokens
                    cost = @{
                        input = 0
                        output = 0
                        cacheRead = 0
                        cacheWrite = 0
                    }
                    compat = @{
                        supportsStore = $false
                        supportsDeveloperRole = $false
                        supportsReasoningEffort = $false
                        maxTokensField = 'max_tokens'
                        thinkingFormat = 'deepseek'
                    }
                }
            )
        }
    }
}
$json = $config | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'models.json'), $json, (New-Object Text.UTF8Encoding($false)))
if ($AllSuites -and ($Attack -or $InjectionTask -or $PSBoundParameters.ContainsKey('UserTask') -or $PSBoundParameters.ContainsKey('Suite'))) {
    throw 'AllSuites runs all clean tasks; do not combine with task, suite or attack filters.'
}
$moduleName = if ($AllSuites) { 'adapters.agentdojo_pi.run_all' } else { 'adapters.agentdojo_pi.run' }
$runArgs = @('-B', '-m', $moduleName, '--mode', $Mode,
    '--action-output-budget', 'model',
    # '--pi-agent-dir', $PSScriptRoot, '--provider', 'local-qwen', '--model', $modelId
    '--pi-agent-dir', $PSScriptRoot, '--provider', 'remote-action', '--model', $modelId)
if (-not $AllSuites) { $runArgs += @('--suite', $Suite) }
if (-not $AllTasks -and -not $AllSuites) { $runArgs += @('--user-task', $UserTask) }
if (($AllTasks -or $AllSuites -or $ContinueOnError) -and -not $StopOnError) { $runArgs += '--continue-on-error' }
if ($Attack) { $runArgs += @('--attack', $Attack) }
if ($InjectionTask) { $runArgs += @('--injection-task', $InjectionTask) }
if ($Check) { $runArgs += '--check' }
if ($Output) { $runArgs += @('--output', $Output) }
$runArgs += @('--ablation', $Ablation)
if ($AuthorizationContracts) { $runArgs += @('--authorization-contracts', $AuthorizationContracts) }
if ($ReadPreflight) { $runArgs += '--read-preflight' }
if ($CalendarReminderWindow) { $runArgs += @('--calendar-reminder-window', $CalendarReminderWindow) }
if ($TrustedCurrentDay) { $runArgs += @('--trusted-current-day', $TrustedCurrentDay) }
if ($TrustedCurrentTime) { $runArgs += @('--trusted-current-time', $TrustedCurrentTime) }
$runArgs += @('--payment-date-policy', $PaymentDatePolicy)
$runArgs += @('--equal-share-policy', $EqualSharePolicy)
$runArgs += @('--intent-format', $IntentFormat)
$runArgs += @('--review-coordination', $ReviewCoordination)
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    # AgentDojo opens UTF-8 YAML/includes without an explicit encoding. Windows
    # locale defaults can silently corrupt resource identities before the model.
    & python -X utf8 @runArgs
    if ($LASTEXITCODE -ne 0) { throw "Qwen evaluation failed with exit code $LASTEXITCODE" }
} finally { Pop-Location }
