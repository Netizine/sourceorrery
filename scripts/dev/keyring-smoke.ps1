<#
.SYNOPSIS
Smoke test of this machine's key in the OS credential store on Windows
(Credential Manager).

.DESCRIPTION
The Windows counterpart of keyring-smoke.sh: every operation the CLI
performs with the credential store, once, in an isolated home. The store
is inspected through `cmdkey /list`, which names generic credentials but
not their attributes, so those checks look for the vault's account string
in the listing and are informational when it does not appear. Nothing
printed is a secret value: the one value stored is a canary generated here
and compared in memory, and the recovery keys go to files in the isolated
home.

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
Remove-Item Env:SOURCEORRERY_RECOVERY_KEY, Env:SOURCEORRERY_RECOVERY_KEY_FILE, Env:SOURCEORRERY_KEYRING, Env:SOURCEORRERY_VAULT -ErrorAction SilentlyContinue
$script:passed = 0
$script:failed = 0
function Pass($what) { $script:passed++; Write-Host "PASS  $what" }
function Fail($what) { $script:failed++; Write-Host "FAIL  $what" -ForegroundColor Red }
function Run([string[]]$CliArgs) {
    # Runs the CLI with piped (empty) input, so a vault that cannot be
    # opened fails instead of prompting; returns [ok, combined output].
    $out = '' | & $Cli @CliArgs 2>&1 | Out-String
    return @(($LASTEXITCODE -eq 0), $out)
}
function Check($what, [string[]]$CliArgs) { $r = Run $CliArgs; if ($r[0]) { Pass $what } else { Fail $what; Write-Host ($r[1] -replace '(?m)^', '      ') } }
function CheckNot($what, [string[]]$CliArgs) { $r = Run $CliArgs; if ($r[0]) { Fail $what } else { Pass $what } }
# What a machine without this store does: no credential store at all,
# optionally with a recovery-key file.
function Elsewhere([scriptblock]$Body, [string]$KeyFile = "") {
    $env:SOURCEORRERY_KEYRING = "off"
    if ($KeyFile) { $env:SOURCEORRERY_RECOVERY_KEY_FILE = $KeyFile }
    try { & $Body } finally { Remove-Item Env:SOURCEORRERY_KEYRING, Env:SOURCEORRERY_RECOVERY_KEY_FILE -ErrorAction SilentlyContinue }
}
function StoreHas($account) { (cmdkey /list 2>$null | Out-String) -match [regex]::Escape($account) }
function StoreCheck($what, $account, $present) {
    $has = StoreHas $account
    if ($has -eq $present) { Pass $what } else { Write-Host "INFO  $what (cmdkey does not show the entry's account; functional checks decide)" }
}
function Json($CliArgs) { ('' | & $Cli -o json @CliArgs 2>$null | Out-String) | ConvertFrom-Json }
# The id of the this-machine key in `vault create -o json`'s report.
function MachineKey($created) { @($created.keys | Where-Object kind -eq "this-machine")[0].id }

try {
    Write-Host "keyring-smoke: $(& $Cli --version) on Windows $([Environment]::OSVersion.Version)"
    Write-Host "  home: $env:SOURCEORRERY_HOME"

    $keyFile = Join-Path $env:SOURCEORRERY_HOME "smoke.key"
    $created = Json @("vault", "create", "smoke", "--recovery-key-out", $keyFile)
    if (-not $created) { Fail "vault create"; exit 1 }
    if (-not $created.this_machine) { Write-Host "keyring-smoke: the credential store is not available"; exit 2 }
    Pass "vault create keeps this machine's key in the store"
    $vaultId = $created.vault.id
    $wrap = MachineKey $created
    $account = "vault/$vaultId/$wrap"
    if ($wrap) { Pass "vault create reports this machine's key" } else { Fail "vault create reports this machine's key" }
    StoreCheck "the store holds the vault's entry ($account)" $account $true

    $canary = "smoke-" + [guid]::NewGuid().ToString("N")
    $set = $canary | & $Cli secret set canary --vault smoke --stdin 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Pass "secret set through this machine's key" } else { Fail "secret set through this machine's key"; Write-Host $set }
    $got = ('' | & $Cli secret get canary --vault smoke --reveal --raw 2>$null | Out-String)
    if ($got.Trim() -eq $canary) { Pass "secret get returns the stored value" } else { Fail "secret get returns the stored value" }
    Check "a second process opens the vault without a prompt" @("secret", "list", "--vault", "smoke")

    Elsewhere { CheckNot "elsewhere, without the recovery key, the vault stays locked" @("secret", "list", "--vault", "smoke") }
    Elsewhere { Check "elsewhere the recovery key opens it" @("secret", "list", "--vault", "smoke") } $keyFile
    StoreCheck "this machine's entry is unchanged" $account $true
    Check "this machine still opens the vault without a prompt" @("secret", "list", "--vault", "smoke")

    Copy-Item "$env:SOURCEORRERY_HOME\vaults\smoke.sorvault" "$env:SOURCEORRERY_HOME\vaults\smoke-copy.sorvault"
    $r = Run @("vault", "destroy", "smoke", "--yes")
    if ($r[0]) { Pass "vault destroy with a copy present" } else { Fail "vault destroy with a copy present" }
    if ($r[1] -match "kept OS-keyring entry") { Pass "destroy reports the entry kept for the copy" } else { Fail "destroy reports the entry kept for the copy" }
    StoreCheck "the entry survives while the copy references it" $account $true
    Check "destroying the copy" @("vault", "destroy", "smoke-copy", "--yes")
    StoreCheck "the entry is removed with the last file" $account $false

    $kept = Json @("vault", "create", "keep", "--recovery-key-out", (Join-Path $env:SOURCEORRERY_HOME "keep.key"))
    if ($kept) { Pass "vault create keep" } else { Fail "vault create keep" }
    $keepAccount = "vault/$($kept.vault.id)/$(MachineKey $kept)"
    Copy-Item "$env:SOURCEORRERY_HOME\vaults\keep.sorvault" "$env:SOURCEORRERY_HOME\vaults\keep-copy.sorvault"
    Check "vault destroy --keep-os-key" @("vault", "destroy", "keep", "--yes", "--keep-os-key")
    StoreCheck "the entry is kept on request" $keepAccount $true
    Check "destroying the copy removes it" @("vault", "destroy", "keep-copy", "--yes")
    StoreCheck "no entry is left behind" $keepAccount $false
}
finally {
    foreach ($name in @("smoke", "smoke-copy", "keep", "keep-copy")) {
        if (Test-Path "$env:SOURCEORRERY_HOME\vaults\$name.sorvault") { '' | & $Cli vault destroy $name --yes 2>$null | Out-Null }
    }
    Remove-Item -Recurse -Force $env:SOURCEORRERY_HOME -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "keyring-smoke: $script:passed passed, $script:failed failed"
if ($script:failed -gt 0) { exit 1 }
exit 0
