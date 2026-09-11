[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "help", "setup", "local-preflight", "model-preflight", "platform-preflight",
        "dry-run", "submit-test", "rehearsal", "monitor", "round2", "round3"
    )]
    [string]$Command = "help",

    [Parameter(Position = 1)]
    [string]$Argument
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

function Get-Setting([string]$Name, [string]$Default) {
    $Value = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    return $Value
}

$Python = Get-Setting "MIDNIGHT_PYTHON" (Join-Path $Root ".venv\Scripts\python.exe")
$PlatformConfig = Get-Setting "MIDNIGHT_PLATFORM_CONFIG" (Join-Path $Root "config\platform.local.yaml")
$Concurrency = Get-Setting "MIDNIGHT_COMPETITION_CONCURRENCY" "8"
$PlatformConcurrency = Get-Setting "MIDNIGHT_PLATFORM_INSTANCE_CONCURRENCY" "2"
$RunTimeout = Get-Setting "MIDNIGHT_COMPETITION_RUN_TIMEOUT" "1620"
$TaskTimeout = Get-Setting "MIDNIGHT_COMPETITION_TASK_TIMEOUT" "1800"
$WaitForChallenges = Get-Setting "MIDNIGHT_COMPETITION_WAIT_FOR_CHALLENGES" "300"

function Show-Usage {
    @"
Usage: .\scripts\competition.ps1 COMMAND [ARG]

Commands:
  setup                 Install Python dependencies, create local templates, build sandboxes
  local-preflight       Check configuration, organizer model, Docker, and all sandboxes
  model-preflight       Check model connection, structured JSON, and tool actions
  platform-preflight    Read and normalize the official challenge inventory
  dry-run ID            Solve one organizer test task without submitting
  submit-test ID        Solve and submit one organizer-authorized test task
  rehearsal             Auto-fetch, re-solve, and submit all test-platform tasks
  monitor RUN_ID        Follow the redacted event stream for a running test
  round2                Start the unattended 27-minute second-stage run
  round3                Start the unattended 27-minute final-stage run

Credentials remain in the ignored .env file and are never printed by this script.
"@
}

function Require-Command([string]$Name, [string]$InstallHint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required command '$Name'. $InstallHint"
    }
}

function Require-Runtime {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        throw "Missing local Python environment: $Python. Run '.\scripts\competition.ps1 setup' first."
    }
}

function Require-PlatformConfig {
    if (-not (Test-Path -LiteralPath $PlatformConfig -PathType Leaf)) {
        throw "Missing ignored platform config: $PlatformConfig"
    }
}

function Ensure-Docker {
    Require-Command "docker" "Install Docker Desktop and enable its WSL 2 Linux-container backend."
    & docker info 1>$null 2>$null
    if ($LASTEXITCODE -eq 0) { return }

    $Desktop = Join-Path $Env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
    if (-not (Test-Path -LiteralPath $Desktop -PathType Leaf)) {
        throw "Docker is installed but its engine is unavailable. Start Docker Desktop."
    }
    Write-Host "Starting Docker Desktop and waiting for the Linux engine..."
    Start-Process -FilePath $Desktop | Out-Null
    $Deadline = [DateTime]::UtcNow.AddMinutes(3)
    do {
        Start-Sleep -Seconds 3
        & docker info 1>$null 2>$null
        if ($LASTEXITCODE -eq 0) { return }
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw "Docker Desktop did not become ready within three minutes."
}

function Invoke-RequiredMidnight([string[]]$Arguments) {
    & $Python -m midnight.app @Arguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Initialize-Midnight {
    Require-Command "uv" "Install uv from https://docs.astral.sh/uv/getting-started/installation/ and reopen PowerShell."
    Ensure-Docker
    & uv sync --extra dev
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    if (-not (Test-Path -LiteralPath (Join-Path $Root ".env"))) {
        Copy-Item -LiteralPath (Join-Path $Root ".env.example") -Destination (Join-Path $Root ".env")
        Write-Host "Created .env. Add the model API settings and team token before model/platform preflight."
    }
    if (-not (Test-Path -LiteralPath $PlatformConfig)) {
        Copy-Item -LiteralPath (Join-Path $Root "config\platform.ichunqiu.example.yaml") -Destination $PlatformConfig
        Write-Host "Created config\platform.local.yaml. Fill it from the organizer API document."
    }

    $PreviousModelsFile = [Environment]::GetEnvironmentVariable("MIDNIGHT_MODELS_FILE", "Process")
    try {
        $Env:MIDNIGHT_MODELS_FILE = "models.stub.yaml"
        Invoke-RequiredMidnight @("--check-config")
        Invoke-RequiredMidnight @("--check-sandboxes")
    }
    finally {
        if ($null -eq $PreviousModelsFile) {
            Remove-Item Env:MIDNIGHT_MODELS_FILE -ErrorAction SilentlyContinue
        }
        else {
            $Env:MIDNIGHT_MODELS_FILE = $PreviousModelsFile
        }
    }
    Write-Host "Midnight installation and offline sandbox validation completed."
}

function Get-RunRoot([string]$RunId) {
    $Path = Join-Path (Join-Path $Root "logs") $RunId
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    return $Path
}

function Get-RunArguments([string]$RunId, [string]$OutputRoot) {
    return @(
        "--platform-config", $PlatformConfig,
        "--run-id", $RunId,
        "--events-path", (Join-Path $OutputRoot "events.jsonl"),
        "--checkpoint-path", (Join-Path $OutputRoot "checkpoints.sqlite"),
        "--submission-ledger-path", (Join-Path $OutputRoot "submissions.sqlite"),
        "--artifacts-root", (Join-Path $OutputRoot "artifacts"),
        "--workspace-root", (Join-Path $OutputRoot "workspaces"),
        "--report-path", (Join-Path $OutputRoot "report.json")
    )
}

function Invoke-Single([string]$Stage, [string]$ChallengeId, [bool]$Submit) {
    $RunId = Get-Setting "MIDNIGHT_RUN_ID" $Stage
    $OutputRoot = Get-RunRoot $RunId
    $Arguments = @(
        "--platform-config", $PlatformConfig,
        "--id", $ChallengeId,
        "--run-id", $RunId,
        "--max-concurrency", "1",
        "--task-timeout", "900",
        "--events-path", (Join-Path $OutputRoot "events.jsonl"),
        "--checkpoint-path", (Join-Path $OutputRoot "checkpoints.sqlite"),
        "--submission-ledger-path", (Join-Path $OutputRoot "submissions.sqlite"),
        "--artifacts-root", (Join-Path $OutputRoot "artifacts"),
        "--workspace-root", (Join-Path $OutputRoot "workspaces"),
        "--report-path", (Join-Path $OutputRoot "report.json")
    )
    if ($Submit) { $Arguments += "--submit" }
    & $Python -m midnight.app @Arguments
    exit $LASTEXITCODE
}

function Invoke-Round([string]$Stage, [bool]$IncludeSolved) {
    $RunId = Get-Setting "MIDNIGHT_RUN_ID" $Stage
    $OutputRoot = Get-RunRoot $RunId
    $Arguments = Get-RunArguments $RunId $OutputRoot
    $Arguments += @(
        "--submit",
        "--max-concurrency", $Concurrency,
        "--platform-instance-concurrency", $PlatformConcurrency,
        "--task-timeout", $TaskTimeout,
        "--run-timeout", $RunTimeout
    )
    if ($IncludeSolved) {
        $Arguments += "--include-solved"
    }
    else {
        $Arguments += @("--wait-for-challenges", $WaitForChallenges)
    }
    & $Python -m midnight.app @Arguments
    exit $LASTEXITCODE
}

switch ($Command) {
    "help" { Show-Usage }
    "setup" { Initialize-Midnight }
    "local-preflight" {
        Require-Runtime
        Ensure-Docker
        Invoke-RequiredMidnight @("--check-config")
        Invoke-RequiredMidnight @("--check-model")
        Invoke-RequiredMidnight @("--check-model-tools")
        Invoke-RequiredMidnight @("--check-sandboxes")
    }
    "model-preflight" {
        Require-Runtime
        Invoke-RequiredMidnight @("--check-config")
        Invoke-RequiredMidnight @("--check-model")
        Invoke-RequiredMidnight @("--check-model-tools")
    }
    "platform-preflight" {
        Require-Runtime
        Require-PlatformConfig
        Invoke-RequiredMidnight @("--platform-config", $PlatformConfig, "--list-only")
    }
    "dry-run" {
        Require-Runtime
        Require-PlatformConfig
        if ([string]::IsNullOrWhiteSpace($Argument)) { throw "dry-run requires a test challenge ID" }
        Invoke-Single "platform-dry-run" $Argument $false
    }
    "submit-test" {
        Require-Runtime
        Require-PlatformConfig
        if ([string]::IsNullOrWhiteSpace($Argument)) { throw "submit-test requires an organizer-authorized challenge ID" }
        Invoke-Single "platform-submit-test" $Argument $true
    }
    "rehearsal" {
        Require-Runtime
        Require-PlatformConfig
        Ensure-Docker
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable("MIDNIGHT_RUN_ID", "Process"))) {
            $Env:MIDNIGHT_RUN_ID = "rehearsal-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")
        }
        Invoke-Round $Env:MIDNIGHT_RUN_ID $true
    }
    "monitor" {
        if ([string]::IsNullOrWhiteSpace($Argument)) { throw "monitor requires a run ID" }
        $EventPath = Join-Path (Join-Path (Join-Path $Root "logs") $Argument) "events.jsonl"
        if (-not (Test-Path -LiteralPath $EventPath)) { throw "No event stream yet: $EventPath" }
        Get-Content -LiteralPath $EventPath -Wait
    }
    "round2" {
        Require-Runtime
        Require-PlatformConfig
        Ensure-Docker
        Invoke-Round "round2" $false
    }
    "round3" {
        Require-Runtime
        Require-PlatformConfig
        Ensure-Docker
        Invoke-Round "round3" $false
    }
}
