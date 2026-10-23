# First run: from a vault to `run`

The first thing to do with SourceOrrery is six steps long: a vault, a first
secret, a way back in if the passphrase is lost, a second factor, the rule
for showing a value, and the manifest that replaces `.env`. The CLI walks
through them on the terminal:

```bash
sourceorrery setup
```

Every step is also one or two ordinary commands, listed below and printed
by `sourceorrery setup --guide` (or by `setup` itself when there is no
terminal, as in a script or a pipe), so nothing the wizard does is special
to it: each step can be redone, undone or scripted later.

> [!NOTE]
> Nothing typed as a secret on these screens is echoed or kept by them: a
> passphrase or value is drawn as dots while it is typed, lives in a buffer
> that is wiped afterwards, and goes to the vault and nowhere else. Two
> things are shown, once, behind a "written down" tick box: a passphrase
> the wizard generated (you have to know it) and the recovery codes.

## 1. Vault

A vault is one encrypted file in your home directory. Its passphrase
derives the key, so it has to be strong, and it cannot be recovered; the
wizard rates what you type as you type it and accepts "good" or better
(the estimate counts common passwords, dictionary-style words with the
usual substitutions, repeats, sequences, years and short length against
it). Or let it generate one: twenty characters from the OS random source,
about 125 bits, shown once.

Where the OS credential store is available (Windows Credential Manager,
macOS Keychain, Secret Service on Linux) the wizard also stores a second
key there, ticked by default, so day-to-day use on this machine does not
prompt; the passphrase stays the way in everywhere else (WSL, Docker, CI,
another machine). A vault that exists already is used as it is.

```bash
sourceorrery vault create development --protector passphrase
sourceorrery vault passphrase generate                                  # if you want one made
sourceorrery vault protector add --kind os-keyring --vault development  # optional
```

## 2. First secret

The first secret is a database password, under the name `database-password`
(`--secret NAME` for another). A database password cannot be weak, so the
same meter applies to a typed value, or the wizard generates a 24-character
one and stores it without ever showing it. Read it later with
`sourceorrery secret get database-password --reveal`, which the guard below
can protect, or hand it to your program with `sourceorrery run`.

```bash
sourceorrery secret set database-password --vault development          # a hidden prompt
sourceorrery vault passphrase generate --length 24 | sourceorrery secret set database-password --vault development
```

## 3. Recovery

Nothing can recover a lost passphrase. What can be done is to have other
ways in, made now: the wizard issues five **recovery codes**, each a
25-character code that unlocks the vault once typed at the passphrase
prompt (or supplied through `SOURCEORRERY_PASSPHRASE`; case, hyphens and
the look-alike letters do not matter). Together they are a second
passphrase, so write them down and keep them apart from this machine; the
wizard does not go on until you tick that you have. Running the command
again replaces the whole set.

An optional **hint** is shown at the passphrase prompt. It is stored in
clear in the vault file and nothing authenticates it, so it is a reminder
for you and never the passphrase in disguise (one that itself unlocks the
vault is refused).

```bash
sourceorrery vault recovery codes --vault development
sourceorrery vault passphrase hint "the usual phrase, with the year" --vault development
```

With the passphrase lost and a code in hand, unlock with the code and set a
new passphrase:

```bash
sourceorrery vault passphrase set --vault development     # the code at the "current" prompt
```

## 4. Second factor

An authenticator app (any that speaks TOTP: the time-based codes of
RFC 6238, six digits every thirty seconds) can be asked for a code before a
value is shown or the vault exported. The wizard draws the enrolment as a
QR code to scan, offers the key for typing where the camera cannot read
the terminal, and keeps the enrolment only once a code from the app has
matched, so a mis-scan cannot lock you out. The key is sealed inside the
vault with the vault's own key: it travels with the file, never through a
server, and a code is accepted once.

```bash
sourceorrery vault 2fa enable --vault development
sourceorrery vault 2fa status --vault development
```

## 5. Reveal guard

Unlocking the vault lets your program read its secrets. The **reveal guard**
is a second check for the moments a person asks to *see* one: with it on,
`secret get --reveal`, `backup` and every change to how the vault unlocks
ask for the vault passphrase again, a code from the app, or both, even when
the OS keyring unlocked the vault. It never applies to `run`, `check`, the
`ui` browser (which shows no value) or the SDKs, so an application keeps
starting without a prompt while an API key read out at the keyboard, by you
or by an agent driving the CLI, asks for the passphrase and the phone.

The wizard offers "the passphrase and a code" once a second factor is
verified, "the passphrase", or nothing. Scripts satisfy the guard with
`SOURCEORRERY_PASSPHRASE` and `--code` / `SOURCEORRERY_TOTP`; a code is never
read from a pipe, so a script without one is refused rather than hung.

```bash
sourceorrery vault guard --reveal passphrase,second-factor --vault development
sourceorrery secret get database-password --vault development --reveal
Passphrase of vault 'development' to reveal a secret:
Code from the app: 123456
```

## 6. Project

The manifest, `sourceorrery.toml`, declares which secrets your project
needs and which vault holds them; it never holds a value, so it is safe to
commit. The wizard writes it (an existing one is kept), checks every
secret it declares against the vault, and shows the command that starts
your program with the secret in its environment.

```bash
sourceorrery init --vault-name development
sourceorrery check
sourceorrery run -- npm start      # DATABASE_PASSWORD is set in the child only
```

## Afterwards

The last screen names what was set up and the commands to go on with:

| To | Run |
|----|-----|
| start your program | `sourceorrery run -- <your command>` |
| see a value (the guard asks for what you chose) | `sourceorrery secret get database-password --vault development --reveal` |
| add a secret, browse the vault, check before a deploy | `sourceorrery secret set NAME --vault development`, `sourceorrery ui`, `sourceorrery check` |
| run headless (WSL, Docker, CI) | `SOURCEORRERY_PASSPHRASE_FILE=/run/secrets/vault sourceorrery run -- <command>` |
| change the passphrase, the hint, the codes, the second factor or the guard | `sourceorrery vault passphrase set`, `vault passphrase hint`, `vault recovery codes`, `vault 2fa`, `vault guard` |
| see all of it at once | `sourceorrery vault info --vault development` |

Every command is in the [CLI reference](cli.md); what the guard, the codes
and the hint do and do not protect against is in the
[threat model](threat-model.md).
