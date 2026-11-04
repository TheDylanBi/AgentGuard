param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('baseline','full','no-semantic-review','no-hard-gate')][string]$Group,
    [Parameter(Mandatory=$true)]
    [ValidateSet('clean','attack')][string]$Phase,
    [switch]$Check
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$tag = [Guid]::NewGuid().ToString('N')
$resultRoot = Join-Path $projectRoot "results/agentdojo_pi_ablation_${Group}_${Phase}_$tag"
$runOptions = @{ Mode='guarded'; IntentFormat='review'; Ablation='full'; Check=$Check.IsPresent }
if ($Group -eq 'baseline') {
    $runOptions.Mode = 'baseline'
    $runOptions.IntentFormat = 'rules'
} else {
    if ($Group -ne 'full') { $runOptions.Ablation = $Group }
}
$launcher = Join-Path $PSScriptRoot 'run-qwen.ps1'
if ($Phase -eq 'clean') {
    & $launcher @runOptions -AllSuites -Output $resultRoot
} else {
    $failedSuites = @()
    foreach ($suite in @('workspace','travel','banking','slack')) {
        try {
            & $launcher @runOptions -Suite $suite -AllTasks -Attack tool_knowledge `
                -Output (Join-Path $resultRoot $suite)
        } catch {
            $failedSuites += $suite
            Write-Warning "Suite $suite failed. Inspect its summary.json and the preceding error."
        }
    }
    if ($failedSuites.Count -gt 0) { throw "Incomplete suites: $($failedSuites -join ', ')" }
}
if (-not $Check) { Write-Host "Ablation results: $resultRoot" }
