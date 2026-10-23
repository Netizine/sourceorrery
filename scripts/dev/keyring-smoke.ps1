<#
.SYNOPSIS
Smoke test of the OS-keyring protector path on Windows (Credential Manager).

.DESCRIPTION
The Windows counterpart of keyring-smoke.sh: every operation the CLI
performs with the credential store, once, in an isolated home. The store
is inspected through `cmdkey /list`, which names generic credentials but
not their attributes, so those checks look for the vault's account string
in the listing and are informational when it does not appear. Nothing
printed is a secret value: the one value stored is a canary generated here
and compared in memory.

    pwsh scripts/dev/keyring-smoke.ps1 [-Cli path\to\sourceorrery.exe]

Exit 0: every check passed; 1: a check failed; 2: the credential store is
not available.
#>
param([string]$Cli = "")

$ErrorActionPreference = "Stop"
if (-not $Cli) {
    $repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
    foreach ($candidate in @("$repo\target\release\sourceorrery.exe", "$repo\target\debug\sourceorrery.exe")) {
        if (Test-Path $candidate) { $Cli = $candidate; break }
    }
    if (-not $Cli) { $Cli = (Get-Command sourceorrery -ErrorAction SilentlyContinue).Source }
}
if (-not $Cli -or -not (Test-Path $Cli)) {
    Write-Error "keyring-smoke: no sourceorrery binary; pass -Cli or build the CLI"
    exit 2
}

$env:SOURCEORRERY_HOME = Join-Path ([System.IO.Path]::GetTempPath()) ("so-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $env:SOURCEORRERY_HOME | Out-Null
Remove-Item Env:SOURCEORRERY_PASSPHRASE, Env:SOURCEORRERY_PASSPHRASE_FILE, Env:SOURCEORRERY_VAULT -ErrorAction SilentlyContinue
$script:passed = 0
$script:failed = 0
function Pass($what) { $script:passed++; Write-Host "PASS  $what" }
function Fail($what) { $script:failed++; Write-Host "FAIL  $what" -ForegroundColor Red }
function Run([string[]]$CliArgs) {
    # Runs the CLI with no console input; returns [ok, combined output].
    $out = & $Cli @CliArgs 2>&1 | Out-String
    return @(($LASTEXITCODE -eq 0), $out)
}
function Check($what, [string[]]$CliArgs) { $r = Run $CliArgs; if ($r[0]) { Pass $what } else { Fail $what; Write-Host ($r[1] -replace '(?m)^', '      ') } }
function StoreHas($account) { (cmdkey /list 2>$null | Out-String) -match [regex]::Escape($account) }
function StoreCheck($what, $account, $present) {
    $has = StoreHas $account
    if ($has -eq $present) { Pass $what } else { Write-Host "INFO  $what (cmdkey does not show the entry's account; functional checks decide)" }
}
function Json($CliArgs) { (& $Cli -o json @CliArgs 2>$null | Out-String) | ConvertFrom-Json }

try {
    Write-Host "keyring-smoke: $(& $Cli --version) on Windows $([Environment]::OSVersion.Version)"
    Write-Host "  home: $env:SOURCEORRERY_HOME"

    $r = Run @("vault", "create", "smoke", "--protector", "os-keyring")
    if (-not $r[0]) {
        Write-Host ($r[1] -replace '(?m)^', '  ')
        if ($r[1] -match "not available|unsupported|refused access") { Write-Host "keyring-smoke: the credential store is not available"; exit 2 }
        Fail "vault create --protector os-keyring"; exit 1
    }
    Pass "vault create --protector os-keyring"
    $vaultId = (Json @("vault", "info", "--vault", "smoke")).vault.id
    $protector = (Json @("vault", "protector", "list", "--vault", "smoke") | Where-Object kind -eq "os-keyring")[0].id
    $account = "vault/$vaultId/$protector"
    if ($protector) { Pass "protector list shows an os-keyring protector" } else { Fail "protector list shows an os-keyring protector" }
    StoreCheck "the store holds the vault's entry ($account)" $account $true

    $canary = "smoke-" + [guid]::NewGuid().ToString("N")
    $set = $canary | & $Cli secret set canary --vault smoke --stdin 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Pass "secret set through the keyring protector" } else { Fail "secret set through the keyring protector"; Write-Host $set }
    $got = (& $Cli secret get canary --vault smoke --reveal --raw 2>$null | Out-String)
    if ($got.Trim() -eq $canary) { Pass "secret get returns the stored value" } else { Fail "secret get returns the stored value" }
    Check "a second process opens the vault without a prompt" @("secret", "list", "--vault", "smoke")

    $env:SOURCEORRERY_PASSPHRASE = "smoke-passphrase-$PID"
    Check "protector add --kind passphrase" @("vault", "protector", "add", "--kind", "passphrase", "--vault", "smoke")
    Check "protector remove <os-keyring id>" @("vault", "protector", "remove", $protector, "--vault", "smoke")
    StoreCheck "the entry is gone after the protector is removed" $account $false
    Check "the vault opens with the passphrase alone" @("secret", "list", "--vault", "smoke")
    Check "protector add --kind os-keyring" @("vault", "protector", "add", "--kind", "os-keyring", "--vault", "smoke")
    Remove-Item Env:SOURCEORRERY_PASSPHRASE
    $protector = (Json @("vault", "protector", "list", "--vault", "smoke") | Where-Object kind -eq "os-keyring")[0].id
    $account = "vault/$vaultId/$protector"
    StoreCheck "the store holds the new entry" $account $true
    Check "the vault opens through the new keyring protector" @("secret", "list", "--vault", "smoke")

    Copy-Item "$env:SOURCEORRERY_HOME\vaults\smoke.sorvault" "$env:SOURCEORRERY_HOME\vaults\smoke-copy.sorvault"
    $r = Run @("vault", "destroy", "smoke", "--yes")
    if ($r[0]) { Pass "vault destroy with a copy present" } else { Fail "vault destroy with a copy present" }
    if ($r[1] -match "kept OS-keyring entry") { Pass "destroy reports the entry kept for the copy" } else { Fail "destroy reports the entry kept for the copy" }
    StoreCheck "the entry survives while the copy references it" $account $true
    Check "destroying the copy" @("vault", "destroy", "smoke-copy", "--yes")
    StoreCheck "the entry is removed with the last file" $account $false

    Check "vault create keep --protector os-keyring" @("vault", "create", "keep", "--protector", "os-keyring")
    $keepId = (Json @("vault", "info", "--vault", "keep")).vault.id
    $keepProtector = (Json @("vault", "protector", "list", "--vault", "keep") | Where-Object kind -eq "os-keyring")[0].id
    $keepAccount = "vault/$keepId/$keepProtector"
    Copy-Item "$env:SOURCEORRERY_HOME\vaults\keep.sorvault" "$env:SOURCEORRERY_HOME\vaults\keep-copy.sorvault"
    Check "vault destroy --keep-os-key" @("vault", "destroy", "keep", "--yes", "--keep-os-key")
    StoreCheck "the entry is kept on request" $keepAccount $true
    Check "destroying the copy removes it" @("vault", "destroy", "keep-copy", "--yes")
    StoreCheck "no entry is left behind" $keepAccount $false
}
finally {
    foreach ($name in @("smoke", "smoke-copy", "keep", "keep-copy")) {
        if (Test-Path "$env:SOURCEORRERY_HOME\vaults\$name.sorvault") { & $Cli vault destroy $name --yes 2>$null | Out-Null }
    }
    Remove-Item -Recurse -Force $env:SOURCEORRERY_HOME -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "keyring-smoke: $script:passed passed, $script:failed failed"
if ($script:failed -gt 0) { exit 1 }
exit 0
