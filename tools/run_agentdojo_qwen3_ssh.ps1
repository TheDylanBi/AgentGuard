[CmdletBinding()]
param(
    [ValidateSet('guarded', 'baseline', 'native')][string]$Mode = 'guarded',
    [ValidateSet('workspace', 'travel', 'banking', 'slack')]
    [string[]]$Suite = @('workspace', 'travel', 'banking', 'slack'),
    [string[]]$UserTask = @(),
    [string[]]$InjectionTask = @(),
    [string]$Attack = '',
    [switch]$FullPlan,
    [switch]$ConnectOnly,
    [switch]$UseExistingTunnel,
    [string]$Output = '',
    [string]$Python = 'D:\miniconda3\envs\agentdojo\python.exe',
    [string]$Node = 'D:\Pi\pi-node\current\node.exe',
    [string]$PiPackage = '',
    [string]$SshHost = $env:INTENTNOTARY_SSH_HOST,
    [ValidateRange(1,65535)][int]$SshPort = 8989,
    [string]$SshKey = (Join-Path $env:USERPROFILE '.ssh/id_ed25519_intentnotary'),
    [ValidateRange(1,65535)][int]$LocalPort = 18001,
    [ValidateRange(1,65535)][int]$RemotePort = 18001,
    [datetime]$PaymentExecutionDay = (Get-Date).Date
)

$ErrorActionPreference = 'Stop'
$project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$model = 'qwen3-32b-awq'
$base = "http://127.0.0.1:$LocalPort"
$api = "$base/v1"
$contextWindow = 32768
$runDay = $PaymentExecutionDay.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
$tunnel = $null
$retainTunnel = $false
$previousEnvironment = @{}

if ($ConnectOnly -and $UseExistingTunnel) {
    throw 'ConnectOnly starts a fresh tunnel. UseExistingTunnel is for benchmark runs.'
}
if (-not $UseExistingTunnel -and [string]::IsNullOrWhiteSpace($SshHost)) {
    throw 'Set INTENTNOTARY_SSH_HOST or pass -SshHost before opening a tunnel.'
}
if ($FullPlan -and ($Mode -ne 'guarded' -or $Attack -or $UserTask.Count -or
        $InjectionTask.Count -or @($Suite | Sort-Object -Unique).Count -ne 4 -or $ConnectOnly)) {
    throw 'FullPlan runs guarded clean, baseline clean and guarded tool_knowledge on all four suites.'
}
if ($InjectionTask.Count -and -not $Attack) {
    throw 'Specify Attack when selecting an injection task.'
}
if (-not $Output) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $id = [guid]::NewGuid().ToString('N').Substring(0, 6)
    $Output = Join-Path $project "results/agentdojo_windows_qwen3_${stamp}_$id"
} elseif (-not [IO.Path]::IsPathRooted($Output)) {
    $Output = Join-Path (Get-Location).Path $Output
}
$run = (New-Item -ItemType Directory -Path $Output -Force).FullName

function Set-RunEnvironment([string]$Name, $Value) {
    if (-not $previousEnvironment.ContainsKey($Name)) {
        $previousEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
    }
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
}

function Write-Status([string]$Message) {
    "$(Get-Date -Format o) $Message" | Set-Content (Join-Path $run 'status.txt') -Encoding UTF8
}

function Invoke-Benchmark([string]$Profile, [string]$LogFolder, [string[]]$Options) {
    $cliArgs = @('-X', 'utf8', '-B', '-u', '-m', 'agentdojo.scripts.benchmark',
        '--model', 'OPENAI_COMPATIBLE', '--model-id', $model, '--benchmark-version', 'v1.2.2',
        '--max-workers', '1', '--logdir', (Join-Path $run $LogFolder))
    if ($Profile -ne 'native') {
        $cliArgs += @('--module-to-load', 'intentnotary_pi_agentdojo')
        Set-RunEnvironment 'INTENTNOTARY_PI_PROFILE' $(if ($Profile -eq 'guarded') { 'operation' } else { 'baseline' })
    }
    Write-Status "Running $Profile ($LogFolder)"
    & $Python @cliArgs @Options
    if ($LASTEXITCODE -ne 0) {
        throw "AgentDojo exited with code $LASTEXITCODE in $LogFolder."
    }
}

try {
    if (-not $UseExistingTunnel) {
        $key = (Resolve-Path -LiteralPath $SshKey).Path
        if (Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction SilentlyContinue) {
            throw "Local port $LocalPort is already in use. Select another port or use -UseExistingTunnel for a verified Qwen3 tunnel."
        }
        $ssh = (Get-Command ssh.exe).Source
        $sshArgs = @('-i', ('"{0}"' -f $key), '-p', "$SshPort", '-o', 'IdentitiesOnly=yes',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ExitOnForwardFailure=yes',
            '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3',
            '-N', '-L', "127.0.0.1:${LocalPort}:127.0.0.1:${RemotePort}", $SshHost)
        $start = @{ FilePath = $ssh; ArgumentList = $sshArgs; WindowStyle = 'Hidden'
                    PassThru = $true; RedirectStandardError = (Join-Path $run 'ssh.log') }
        $tunnel = Start-Process @start
        for ($attempt = 0; $attempt -lt 25; $attempt++) {
            $tunnel.Refresh()
            if ($tunnel.HasExited) { throw "SSH could not start. See $(Join-Path $run 'ssh.log')." }
            if (Get-NetTCPConnection -State Listen -LocalPort $LocalPort -OwningProcess $tunnel.Id -ErrorAction SilentlyContinue) {
                break
            }
            Start-Sleep -Milliseconds 400
        }
        if (-not (Get-NetTCPConnection -State Listen -LocalPort $LocalPort -OwningProcess $tunnel.Id -ErrorAction SilentlyContinue)) {
            throw "SSH did not bind port $LocalPort. See $(Join-Path $run 'ssh.log')."
        }
    }
    $live = Invoke-RestMethod "$api/models" -TimeoutSec 15
    if (-not ($live.data | Where-Object { $_.id -eq $model -and $_.max_model_len -eq $contextWindow })) {
        throw "Expected $model with a $contextWindow-token context at $api."
    }
    Write-Host "Qwen3 API: $api ($model)"
    if ($ConnectOnly) {
        Write-Host "SSH PID: $($tunnel.Id). Stop the tunnel with: Stop-Process -Id $($tunnel.Id)"
        Write-Status "SSH forwarding active on $api (PID $($tunnel.Id))"
        $retainTunnel = $true
        return
    }

    $Python = (Get-Command $Python).Source
    if ($Mode -ne 'native') {
        $Node = (Get-Command $Node).Source
        if (-not $PiPackage) {
            $PiPackage = Join-Path (Split-Path $Node) 'node_modules/@earendil-works/pi-coding-agent'
        }
        $PiPackage = (Resolve-Path -LiteralPath $PiPackage).Path
        if (-not (Test-Path -LiteralPath (Join-Path $PiPackage 'dist/index.js') -PathType Leaf)) {
            throw "Pi package entry point is missing at $PiPackage."
        }
        $piConfig = (New-Item -ItemType Directory -Path (Join-Path $run 'pi-config') -Force).FullName
        $modelConfig = @{ providers = @{ 'remote-action' = @{
            baseUrl = $api; api = 'openai-completions'; apiKey = 'local'
            models = @(@{
                id = $model; name = 'Qwen3-32B-AWQ'; reasoning = $true; input = @('text')
                contextWindow = $contextWindow; maxTokens = 2048
                cost = @{ input = 0; output = 0; cacheRead = 0; cacheWrite = 0 }
                compat = @{ supportsStore = $false; supportsDeveloperRole = $false
                    supportsReasoningEffort = $false; maxTokensField = 'max_tokens' }
            })
        } } }
        $utf8 = [Text.UTF8Encoding]::new($false)
        [IO.File]::WriteAllText((Join-Path $piConfig 'auth.json'), '{}', $utf8)
        [IO.File]::WriteAllText((Join-Path $piConfig 'models.json'), ($modelConfig | ConvertTo-Json -Depth 12), $utf8)
        Set-RunEnvironment 'INTENTNOTARY_PI_PACKAGE' $PiPackage
        Set-RunEnvironment 'INTENTNOTARY_PI_AGENT_DIR' $piConfig
        Set-RunEnvironment 'INTENTNOTARY_PI_NODE' $Node
        Set-RunEnvironment 'INTENTNOTARY_PI_VLLM_TOKENIZE' '1'
        Set-RunEnvironment 'INTENTNOTARY_PAYMENT_EXECUTION_DAY' $runDay
        Set-RunEnvironment 'INTENTNOTARY_PI_CAPTURE_REVIEW' $null
        foreach ($item in (Get-ChildItem Env: | Where-Object { $_.Name -match '^(ICB_REVIEW_|ICB_INTENT_LLM_)' })) {
            Set-RunEnvironment $item.Name $null
        }
        Set-RunEnvironment 'ICB_INTENT_LLM_BASE_URL' $api
        Set-RunEnvironment 'ICB_INTENT_LLM_MODEL' $model
        Set-RunEnvironment 'ICB_INTENT_LLM_API_KEY' 'local'
        Set-RunEnvironment 'ICB_INTENT_LLM_TIMEOUT_SECONDS' '120'
        Set-RunEnvironment 'ICB_REVIEW_CALL_TIMEOUT_SECONDS' '120'
        Set-RunEnvironment 'ICB_REVIEW_OUTPUT_FORMAT' 'text'
        Set-RunEnvironment 'ICB_REVIEW_RETRY_OUTPUT_FORMAT' 'text'
        Set-RunEnvironment 'ICB_REVIEW_ENABLE_THINKING' 'true'
        Set-RunEnvironment 'ICB_REVIEW_RETRY_ENABLE_THINKING' 'true'
    }
    Set-RunEnvironment 'OPENAI_COMPATIBLE_BASE_URL' $api
    Set-RunEnvironment 'OPENAI_COMPATIBLE_API_KEY' 'local'
    $pythonPath = @((Join-Path $project 'tools'), $project, $env:PYTHONPATH) | Where-Object { $_ }
    Set-RunEnvironment 'PYTHONPATH' ($pythonPath -join [IO.Path]::PathSeparator)
    $scratch = (New-Item -ItemType Directory -Path (Join-Path $run 'scratch') -Force).FullName
    Set-RunEnvironment 'TEMP' $scratch
    Set-RunEnvironment 'TMP' $scratch
    Push-Location $project
    try {
        $options = @()
        foreach ($name in $Suite) { $options += @('--suite', $name) }
        if ($FullPlan) {
            Invoke-Benchmark 'guarded' 'guarded-clean' $options
            Invoke-Benchmark 'baseline' 'baseline-clean' $options
            Invoke-Benchmark 'guarded' 'guarded-attack' ($options + @('--attack', 'tool_knowledge'))
        } else {
            foreach ($name in $UserTask) { $options += @('--user-task', $name) }
            foreach ($name in $InjectionTask) { $options += @('--injection-task', $name) }
            if ($Attack) { $options += @('--attack', $Attack) }
            $logFolder = if ($Attack) { "$Mode-attack" } else { $Mode }
            Invoke-Benchmark $Mode $logFolder $options
        }
        Write-Status 'Complete'
    } finally {
        Pop-Location
    }
} catch {
    Write-Status "Stopped: $($_.Exception.Message)"
    throw
} finally {
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    if ($tunnel -and -not $retainTunnel) {
        $tunnel.Refresh()
        if (-not $tunnel.HasExited) { Stop-Process -InputObject $tunnel }
    }
}
