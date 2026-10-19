# One-click ZombieShield demo on Windows: checks prerequisites, creates .env, fetches the Sock Shop
# repositories, builds and starts everything, generates demo traffic, runs the pipeline and opens the UI.
# Started by demo.cmd in the repository root. Everything is also written to scripts\demo.log.
param([switch]$Fresh)

# Native tools (docker, git) report progress on stderr; Windows PowerShell 5.1 would turn that into
# terminating errors under "Stop", so failures are detected from exit codes instead.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
try { Start-Transcript -Path (Join-Path $PSScriptRoot "demo.log") -Force | Out-Null } catch { }

function Step($text) { Write-Host ""; Write-Host "== $text" -ForegroundColor Cyan }
function Ok($text) { Write-Host "   $text" -ForegroundColor Green }
function Info($text) { Write-Host "   $text" }
function Fail($text) {
    Write-Host ""; Write-Host "   $text" -ForegroundColor Red
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}
function NewSecret([int]$bytes) {
    $buffer = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    return ([Convert]::ToBase64String($buffer) -replace '[+/=]', '')
}

# ---------------------------------------------------------------- prerequisites
Step "Checking Docker"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "Docker is not installed. Install Docker Desktop (https://www.docker.com/products/docker-desktop/), start it once, then run demo.cmd again."
}
$dockerReady = $false
& docker info *> $null
if ($LASTEXITCODE -eq 0) { $dockerReady = $true }
if (-not $dockerReady) {
    $candidates = @("$env:LOCALAPPDATA\Programs\DockerDesktop\Docker Desktop.exe", "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe")
    $exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($exe) { Info "Starting Docker Desktop..."; Start-Process $exe | Out-Null }
    for ($i = 0; $i -lt 60 -and -not $dockerReady; $i++) {
        Start-Sleep -Seconds 5
        & docker info *> $null
        if ($LASTEXITCODE -eq 0) { $dockerReady = $true }
    }
}
if (-not $dockerReady) { Fail "Docker Desktop is not running. Start it, wait until it says 'Engine running', then run demo.cmd again." }
Ok "Docker is running"

# ---------------------------------------------------------------- .env
Step "Checking configuration (.env)"
$envFile = Join-Path $Root ".env"
if (-not (Test-Path $envFile)) {
    $text = Get-Content (Join-Path $Root ".env.example") -Raw
    $db = NewSecret 18
    $text = $text.Replace("CHANGE-ME-db-password", $db)
    $text = $text.Replace("CHANGE-ME-to-a-random-string-of-at-least-32-characters", (NewSecret 48))
    $text = $text.Replace("CHANGE-ME-admin-password", (NewSecret 12))
    $text = $text.Replace("CHANGE-ME-analyst-password", (NewSecret 12))
    $text = $text.Replace("CHANGE-ME-random-salt", (NewSecret 24))
    Set-Content -Path $envFile -Value $text -NoNewline -Encoding ASCII
    Ok "Created .env with random passwords and secrets"
} else {
    $text = Get-Content $envFile -Raw
    if ($text -match "(?m)^VITE_API_BASE_URL=http://localhost:8000\s*$") {
        $text = $text -replace "(?m)^VITE_API_BASE_URL=http://localhost:8000(\s*)$", 'VITE_API_BASE_URL=/api$1'
        Set-Content -Path $envFile -Value $text -NoNewline -Encoding ASCII
        Ok "Updated VITE_API_BASE_URL to /api (the UI now reaches the backend through its own proxy)"
    } else { Ok ".env found" }
}
$settings = @{}
Get-Content $envFile | Where-Object { $_ -match '^\s*([A-Z_]+)=(.*)$' } | ForEach-Object { $settings[$Matches[1]] = $Matches[2].Trim() }

# ---------------------------------------------------------------- Sock Shop source code
Step "Checking the Sock Shop repositories"
$repos = "front-end", "catalogue", "user", "carts", "orders", "payment", "shipping"
$missing = $repos | Where-Object { -not (Test-Path (Join-Path $Root "discovery-repositories\$_\.git")) }
if ($missing) {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Fail "Git is needed to download the Sock Shop repositories. Install Git for Windows, then run demo.cmd again." }
    foreach ($repo in $missing) {
        Info "Cloning $repo (with full history)..."
        & git clone --quiet "https://github.com/microservices-demo/$repo" (Join-Path $Root "discovery-repositories\$repo")
        if ($LASTEXITCODE -ne 0) { Fail "Could not clone $repo. Check your internet connection and try again." }
    }
}
Ok "All 7 repositories present"

# ---------------------------------------------------------------- containers
if ($Fresh) {
    Step "Resetting ZombieShield's data for a clean demo"
    & docker compose --profile sockshop down -v --remove-orphans
    Ok "Previous containers and data removed"
}
Step "Building and starting ZombieShield and Sock Shop (the first run downloads several GB)"
& docker compose --profile sockshop up -d --build
if ($LASTEXITCODE -ne 0) { Fail "docker compose could not start the stack. Scroll up for the error, or run: docker compose --profile sockshop logs" }

Step "Waiting for the backend"
$healthy = $false
for ($i = 0; $i -lt 90 -and -not $healthy; $i++) {
    try { if ((Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://localhost:8000/health").StatusCode -eq 200) { $healthy = $true } } catch { Start-Sleep -Seconds 2 }
}
if (-not $healthy) { Fail "The backend did not start. See: docker compose logs backend" }
Ok "Backend is healthy"

# ---------------------------------------------------------------- demo data + pipeline
Step "Generating demo traffic and running the pipeline"
& docker compose exec -T backend python scripts/demo_seed.py
if ($LASTEXITCODE -ne 0) { Fail "Demo setup did not finish. The UI still works; see the Pipeline page for details." }

# ---------------------------------------------------------------- done
Step "Ready"
Ok "ZombieShield:  http://localhost:5173"
Ok "Sock Shop:     http://localhost:8079   (through the ZombieShield-managed gateway)"
Ok "API docs:      http://localhost:8000/docs"
Info ("Sign in as '" + $settings["ADMIN_USERNAME"] + "' with password '" + $settings["ADMIN_PASSWORD"] + "' (admin), or '" + $settings["ANALYST_USERNAME"] + "' / '" + $settings["ANALYST_PASSWORD"] + "' (analyst). Both are in .env.")
Info "Walkthrough: docs\DEMO.md. Stop everything with demo-stop.cmd."
Start-Process "http://localhost:5173"
try { Stop-Transcript | Out-Null } catch { }
