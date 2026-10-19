# Clones the Sock Shop service repositories (with full history) for Git discovery.
$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot "..\discovery-repositories"
foreach ($repo in "front-end","catalogue","user","carts","orders","payment","shipping") {
    $target = Join-Path $root $repo
    if (Test-Path $target) { Write-Host "$repo already present"; continue }
    git clone "https://github.com/microservices-demo/$repo" $target
}
Write-Host "Done. Start everything with: docker compose --profile sockshop up --build"
