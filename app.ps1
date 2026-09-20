[CmdletBinding()]
param(
    [string]$App,
    [ValidateSet('build', 'test', 'lint', 'doc', 'clean')]
    [string]$Action = 'build'
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if ($Action -eq 'clean') {
        & cargo clean
        exit $LASTEXITCODE
    }
    $apps = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'apps.json') -Raw | ConvertFrom-Json
    if (-not $App) {
        $apps | Select-Object app, algorithm, mode | Format-Table -AutoSize
        $App = Read-Host 'Choose app number (for example 4 or a4)'
    }
    if ($App -match '^\d+$') { $App = 'a' + $App }
    if ($App -notin $apps.app) { throw "Unknown app: $App" }
    switch ($Action) {
        'build' { & cargo build --locked --release -p $App }
        'test' { & cargo test --locked -p $App -- --test-threads=2 }
        'lint' { & cargo clippy --locked -p $App --all-targets -- -D warnings }
        'doc' { & cargo doc --locked -p $App --no-deps }
    }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ($Action -eq 'build') {
        $metadata = & cargo metadata --locked --no-deps --format-version 1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $target = ($metadata | ConvertFrom-Json).target_directory
        $binary = Join-Path $target "release/$App.exe"
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
            throw 'Expected native Windows binary not found; check CARGO_BUILD_TARGET.'
        }
        $destination = Join-Path $PSScriptRoot "dist/$App"
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Copy-Item -LiteralPath $binary -Destination (Join-Path $destination "$App.exe")
        Write-Host "Built $App`: $destination"
    }
} finally { Pop-Location }
