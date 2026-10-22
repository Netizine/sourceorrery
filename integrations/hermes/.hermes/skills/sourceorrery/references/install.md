# Installing the SourceOrrery CLI

The `sourceorrery` command creates vaults and stores secrets; the SDKs only
read them. Install it once per machine. If your environment asks before
installing software, ask the user first.

Two ways, either is fine:

- **A prebuilt binary** from the GitHub release: no toolchain needed.
  Windows, macOS and Linux (glibc), x64 and arm64.
- **`cargo install --locked sourceorrery-cli`**: needs Rust 1.88 or newer,
  a C compiler, and on Linux `pkg-config` and `libdbus-1-dev`.

Every archive is listed in the release's `SHA256SUMS`. Check it before you
run anything you downloaded, and stop if the check fails.

## Linux and macOS

```bash
version=$(curl -fsSL https://api.github.com/repos/Netizine/sourceorrery/releases/latest \
  | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)               target=x86_64-unknown-linux-gnu ;;
  Linux-aarch64|Linux-arm64)  target=aarch64-unknown-linux-gnu ;;
  Darwin-arm64)               target=aarch64-apple-darwin ;;
  Darwin-x86_64)              target=x86_64-apple-darwin ;;
esac
archive="sourceorrery-$version-$target"
base="https://github.com/Netizine/sourceorrery/releases/download/v$version"
curl -fsSLO "$base/$archive.tar.gz"
curl -fsSLO "$base/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS        # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
tar xzf "$archive.tar.gz"
mkdir -p "$HOME/.local/bin" && install "$archive/sourceorrery" "$HOME/.local/bin/"
sourceorrery --version
```

The check must print `OK` for the archive. If `~/.local/bin` is not on the
`PATH`, tell the user or install to `/usr/local/bin` with `sudo install`
instead.

## Windows (PowerShell)

```powershell
$version = (Invoke-RestMethod https://api.github.com/repos/Netizine/sourceorrery/releases/latest).tag_name.TrimStart('v')
$target = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$archive = "sourceorrery-$version-$target.zip"
$base = "https://github.com/Netizine/sourceorrery/releases/download/v$version"
Invoke-WebRequest "$base/$archive" -OutFile $archive
Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS
$hash = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLower()
if (-not (Select-String -Path SHA256SUMS -SimpleMatch "$hash  $archive")) { throw "checksum mismatch: do not use $archive" }
$dir = "$env:LOCALAPPDATA\Programs\sourceorrery"
Expand-Archive $archive -DestinationPath $dir -Force
[Environment]::SetEnvironmentVariable('Path', "$([Environment]::GetEnvironmentVariable('Path', 'User'));$dir", 'User')
$env:Path += ";$dir"
sourceorrery --version
```

## With Cargo

```bash
cargo install --locked sourceorrery-cli
```

`--locked` builds with the dependency versions the release was tested
with. On a server that will only ever use passphrases, add
`--no-default-features` to leave out the OS credential store (and the
`libdbus-1-dev` requirement).

## After installing

```bash
sourceorrery vault create development
```

The vault key goes into the OS credential store (Windows Credential
Manager, macOS Keychain, Secret Service on Linux) and nothing has to be
typed. The CLI never makes network requests: installing is the only
download.

## Headless

Containers, CI runners, WSL and servers without a desktop session have no
credential store. There the vault is protected by a passphrase, which the
user chooses and types; never invent one or write it into the repository.

- A new vault: the user runs
  `sourceorrery vault create ci --protector passphrase`.
- An existing vault that should also open headless: on a machine that can
  already unlock it, the user runs
  `sourceorrery vault protector add --kind passphrase --vault development`.
- Unlocking: point `SOURCEORRERY_PASSPHRASE_FILE` (or `--passphrase-file`)
  at a file that holds the passphrase and that only that user can read,
  for example a Docker or Kubernetes secret at `/run/secrets/...` or a
  file a CI job writes from its own secret store into a temporary
  directory. `SOURCEORRERY_PASSPHRASE` works too but is visible to process
  inspection.
- `SOURCEORRERY_HOME` says where the vault files live, for example a
  mounted volume. Vault files (`*.sorvault`) are never committed.

Docker, Compose and CI examples: https://sourceorrery.ai/guides/headless/
