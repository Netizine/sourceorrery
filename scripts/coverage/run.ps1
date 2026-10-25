<#
.SYNOPSIS
Checks local coverage prerequisites or runs selected reports without uploading.
.EXAMPLE
pwsh scripts/coverage/run.ps1 -Target site -Check
.EXAMPLE
pwsh scripts/coverage/run.ps1 -Target dotnet
.EXAMPLE
pwsh scripts/coverage/run.ps1 -Target all -Distribution Ubuntu
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'site', 'dotnet')][string]$Target = 'all',
    [switch]$Check,
    [string]$Distribution = 'Ubuntu'
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))

function Invoke-Checked {
    param([string]$Command, [string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Coverage command failed ($LASTEXITCODE): $Command" }
}

Push-Location $repo
try {
    if ($Target -eq 'all') {
        if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
            throw 'All-language coverage needs Ubuntu/WSL. GitHub Actions generates it automatically; local collection is optional. Use -Target site or -Target dotnet for native Windows reports.'
        }
        # Pass paths as arguments, never interpolate them into shell commands.
        $linuxPath = & wsl.exe --distribution $Distribution --exec wslpath -a $repo
        if ($LASTEXITCODE -ne 0) {
            throw "The '$Distribution' WSL distribution is unavailable. Open an installed Ubuntu shell and follow docs/coverage.md, or use GitHub Actions reports. Nothing was installed."
        }
        $arguments = @('--distribution', $Distribution, '--cd', $linuxPath.Trim(), '--exec', 'bash', 'scripts/coverage/run.sh')
        if ($Check) { $arguments += '--check' }
        Invoke-Checked 'wsl.exe' $arguments
        return
    }

    $missing = [Collections.Generic.List[string]]::new()
    if ($Target -eq 'site') {
        if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
            $missing.Add('Node >=22.19 (Node 24 recommended)')
        } else {
            & node scripts/coverage/check-node.mjs
            if ($LASTEXITCODE -ne 0) { $missing.Add('Resolve the Node/dependency checks above before collecting coverage.') }
        }
    } else {
        foreach ($command in @('cargo', 'dotnet')) {
            if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { $missing.Add($command) }
        }
        if (Get-Command dotnet -ErrorAction SilentlyContinue) {
            if (-not ((& dotnet --list-sdks) -match '^10\.')) { $missing.Add('the .NET 10 SDK') }
        }
        # Windows bash.exe can also mean WSL; the fixture here needs Git Bash.
        $gitBash = Join-Path $env:ProgramFiles 'Git/bin/bash.exe'
        if (-not (Test-Path -LiteralPath $gitBash)) { $missing.Add('Git for Windows (Git Bash) in Program Files') }
    }
    if ($missing.Count -gt 0) { throw ("Missing prerequisites:`n - " + ($missing -join "`n - ")) }
    if ($Check) {
        Write-Host "Prerequisites ready for $Target coverage. No tests or uploads were run."
        return
    }
    if ($Target -eq 'site') {
        $arguments = @(
            'scripts/coverage/node_modules/c8/bin/c8.js', '--all',
            '--src', 'site/plugins', '--src', 'site/src/lib', '--src', 'site/scripts',
            '--include', 'site/plugins/**/*.mjs', '--include', 'site/src/lib/**/*.mjs', '--include', 'site/scripts/**/*.mjs',
            '--exclude', '**/*.test.mjs', '--reporter=lcovonly', '--reporter=text-summary',
            '--reports-dir', 'coverage/site', '--temp-directory', 'coverage/site/tmp'
        )
        $tests = @(Get-ChildItem -LiteralPath 'site/scripts' -Filter '*.test.mjs' | ForEach-Object FullName)
        if ($tests.Count -eq 0) { throw 'No site tooling tests were found.' }
        Invoke-Checked 'node' ($arguments + @('node', '--test') + $tests)
        $savedTelemetry = [Environment]::GetEnvironmentVariable('ASTRO_TELEMETRY_DISABLED', 'Process')
        try {
            $env:ASTRO_TELEMETRY_DISABLED = '1'
            Invoke-Checked 'node' ($arguments + @('--clean=false', 'npm', '--prefix', 'site', 'run', 'build'))
        } finally {
            [Environment]::SetEnvironmentVariable('ASTRO_TELEMETRY_DISABLED', $savedTelemetry, 'Process')
        }
        Write-Host 'Report: coverage/site/lcov.info. Nothing was uploaded.'
        return
    }

    $names = @('GITHUB_ENV', 'CARGO_TARGET_DIR', 'SOURCEORRERY_HOME', 'SOURCEORRERY_RECOVERY_KEY',
        'SOURCEORRERY_TEST_VAULT', 'SOURCEORRERY_TEST_MANIFEST', 'SOURCEORRERY_TEST_OLD_VERSION',
        'SOURCEORRERY_NATIVE_DIR', 'SOURCEORRERY_CLI')
    $saved = @{}
    foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    try {
        $env:CARGO_TARGET_DIR = Join-Path $repo 'target/coverage-fixture'
        Invoke-Checked 'cargo' @('build', '--locked', '-p', 'sourceorrery-cli', '-p', 'sourceorrery-ffi')
        $fixture = Join-Path $repo ('coverage/fixture.' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $fixture | Out-Null
        $env:GITHUB_ENV = (Join-Path $fixture 'environment').Replace('\', '/')
        $env:SOURCEORRERY_NATIVE_DIR = (Join-Path $env:CARGO_TARGET_DIR 'debug').Replace('\', '/')
        $env:SOURCEORRERY_CLI = "$env:SOURCEORRERY_NATIVE_DIR/sourceorrery.exe"
        Invoke-Checked $gitBash @('scripts/ci/fixture-vault.sh', (Join-Path $fixture 'home').Replace('\', '/'))
        foreach ($line in Get-Content -LiteralPath $env:GITHUB_ENV) {
            $pair = $line -split '=', 2
            if ($pair.Count -ne 2 -or $pair[0] -notin $names -or -not $pair[0].StartsWith('SOURCEORRERY_')) {
                throw 'Unexpected SDK fixture environment entry.'
            }
            [Environment]::SetEnvironmentVariable($pair[0], $pair[1], 'Process')
        }
        Invoke-Checked 'dotnet' @('test', 'bindings/dotnet/SourceOrrery.Tests/SourceOrrery.Tests.csproj', '-c', 'Release', '-p:CollectCoverage=true')
        Write-Host 'Report: coverage/dotnet.xml. Nothing was uploaded.'
    } finally {
        foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    }
} finally {
    Pop-Location
}
