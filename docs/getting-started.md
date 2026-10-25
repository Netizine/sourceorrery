# First run: from a vault to `run`

The first run is four steps: a vault, its secrets, a project's manifest,
and the command that starts your program with the secrets in its
environment instead of a `.env` file. The vault is set up on screens:

```bash
sourceorrery setup
```

Every screen has a command-line equivalent, so a script or CI does the same
without a terminal (`sourceorrery setup --guide` prints it).

> [!NOTE]
> Nothing typed as a secret on these screens is echoed or kept by them: a
> password, a key or a value is drawn as dots while it is typed, lives in a
> buffer that is wiped afterwards, and goes to the vault and nowhere else.
> Three things are shown, once, by design: a password the screens
> generated, the authenticator key (with its QR code) until the app has
> proved it has it, and the recovery key, behind a "written down" tick.

## 1. A vault

A vault is one encrypted file in your home directory. It holds your
secrets, or the catalog of the ones a provider keeps for it, and the record
of everything done with them. Its key is kept twice:

* **This machine's key**, in the OS credential store (Windows Credential
  Manager, macOS Keychain, Secret Service on Linux). This machine opens the
  vault without asking.
* **The recovery key**, shown once when the vault is made. It opens the
  vault anywhere else: WSL, a container, CI, another machine, an exported
  copy. Write it down and keep it apart from this machine; nothing else
  recovers the vault when this machine's key is gone.

`setup` walks through the rest on screens, and nothing is written until
its review confirms:

* **The view check** (optional): a password, and a code from an
  authenticator app on top of it, asked before anyone *views* the vault or
  reveals a value (`ui`, `secret list`, `secret get`, `audit`). It is a
  check, not encryption: `run`, `check`, `init` and your applications
  never ask it, so programs start without a prompt while a key read out at
  the keyboard, by you or by an agent, asks for more. A password must rate
  "good" on the strength meter, or the screens generate one; the
  authenticator is enrolled from a QR code and kept only once a code from
  the app has matched.
* **Storage**: where the vault keeps secrets. The vault file always, and
  HashiCorp Vault, AWS Secrets Manager or Azure Key Vault through a
  connection the vault holds, signing in the way the provider's own tools
  do on this machine or with credentials stored in the vault, sealed.
  **Test connection** makes one metadata call before anything is saved.

<!-- walkthrough: setup -->

Without a terminal, one command does the same (the authenticator is
enrolled on the screens only):

```bash
sourceorrery vault create development --recovery-key-out development.recovery-key \
  --password-file password.txt
```

## 2. Its secrets

Add secrets in the browser (`a`: the name, where it is kept, then the value
at a hidden prompt), or from a script, one at a time. A value is never a
command-line argument:

```bash
sourceorrery ui
sourceorrery secret set database-password --vault development          # a hidden prompt
printf '%s' "$KEY" | sourceorrery secret set stripe-api-key --vault development --stdin \
  --storage aws-secrets-manager --description "Card payments"
```

An existing `.env` file moves in whole with `sourceorrery import .env`.

<!-- walkthrough: browser -->

## 3. A project

The manifest, `sourceorrery.toml`, declares which secrets a project uses
and which vault holds them. It never holds a value, so it is safe to
commit. In the project's folder:

```bash
sourceorrery init
```

On a terminal, `init` shows the vault's secrets as a list to tick (with
**All**), loops over any new ones the project needs (stored in the vault as
they are added), and writes the manifest after a review; the vault records
the folder, which the `ui` shows under Projects. An existing manifest is
added to, in place. Without a terminal, `init --all` or `init --secret
NAME` picks secrets by name.

<!-- walkthrough: init -->

## 4. Run

```bash
sourceorrery check
sourceorrery run -- npm start      # DATABASE_PASSWORD is set in the child only
```

`check` reads metadata only; `run` resolves every secret, wherever it is
kept, and starts your program with them in its environment.

## Elsewhere: WSL, containers, CI

Where this machine's key is not available, give the vault its recovery
key from a file or the environment:

```bash
export SOURCEORRERY_HOME=/mnt/c/Users/me/AppData/Local/sourceorrery   # the same vaults, from WSL
export SOURCEORRERY_RECOVERY_KEY_FILE=/run/secrets/development.recovery-key
sourceorrery run -- ./deploy.sh
```

To move a vault to another machine, `vault export` writes a copy that
opens with its recovery key only, and `vault import` brings it in there.

## Afterwards

| To | Run |
|----|-----|
| browse the vault, add and change secrets, see its projects | `sourceorrery ui` |
| change the view check, the recovery key or the storage | `sourceorrery vault create development` (the setup screens), or `c` in the browser |
| see a value (the view check asks what you chose) | `sourceorrery secret get database-password --reveal` |
| check before a deploy | `sourceorrery check` |
| move the vault | `sourceorrery vault export --out FILE`, then `vault import FILE` |

Every command is in the [CLI reference](cli.md); what the view check and
the recovery key do and do not protect against is in the
[threat model](threat-model.md).
