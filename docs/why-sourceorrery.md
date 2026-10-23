# Why SourceOrrery?

SourceOrrery was created to keep reusable credentials out of the files and
conversations used to build software. An application needs a password to
connect to a database. Reviewing its configuration, writing a test or asking
a coding agent to refactor the connection code usually needs only the name
of that password and how the application obtains it.

The design follows from that distinction: keep values in an encrypted local
vault, declare requirements in a version-controlled manifest, and resolve
credentials when the application runs. Make inspection useful without
printing a secret, and give credentials a lifecycle beyond copying a line
between `.env` files.

> [!IMPORTANT]
> **The boundary in 0.1.4:** SourceOrrery reduces plaintext storage and
> accidental disclosure in development workflows. It does not isolate an
> agent or other program that can unlock your vault with your OS credentials
> or passphrase. The authenticated broker is planned work; see the
> [threat model](threat-model.md).

## Why an ignored `.env` file is still a secret file

`.env` is a convenient configuration format. Its contents remain plaintext
unless something else protects them. Adding the file to `.gitignore`
influences what Git tracks; it does not change who can open the file. Git
also makes clear that ignore rules do not affect files already tracked.
See the [Git ignore documentation](https://git-scm.com/docs/gitignore).

A file outside Git can still be read by a terminal command, a dependency
installer, a debugging tool or a coding agent with filesystem access. It can
also end up in a pasted diagnostic, a backup or a shared project archive.
Keeping it out of a commit addresses one route of exposure.

Coding agents make this more pressing because they combine reading project
material with acting on it. An issue, repository instruction or tool result
can influence what they read or execute next. Four different failures matter:

- **Accidental disclosure:** configuration is copied into a transcript, log
  or generated source file during ordinary troubleshooting.
- **Prompt injection:** attacker-controlled text steers an agent toward an
  unintended action, such as exposing a credential.
- **Tool vulnerabilities:** file readers or project configuration processing
  cross a boundary that an approval or sandbox was meant to enforce.
- **Untrusted code:** an installed dependency reads credentials using the
  permissions of the process running it.

Moving a credential into an environment variable does not make it
inaccessible to the process receiving it. Similarly, instructions asking an
agent to avoid secrets help cooperative workflows but do not enforce access
control.

## Evidence from incidents and research

The examples below were checked against primary sources on **23 October
2026**. Research demonstrations and investigated intrusions establish
different things, so each example identifies which evidence it provides.

### Malicious repository configuration

**Security research — Check Point, 25 February 2026.** Researchers showed
that malicious Claude Code project configuration could trigger command
execution or redirect requests containing an API key before repository trust
was approved. Anthropic's advisories identify CVE-2025-59536 and
CVE-2026-21852 and record the fixes. These were disclosed vulnerabilities
and controlled demonstrations; the publications do not establish criminal
financial losses.

The relevant lesson is that trusting repository content can grant authority
beyond reading source code. A secret in the agent's own environment can be
exposed without a committed `.env` file.

Sources: [Check Point's research](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/),
[Anthropic's command-execution advisory](https://github.com/anthropics/claude-code/security/advisories/GHSA-4fgq-fpq9-mr3g),
[Anthropic's credential-exposure advisory](https://github.com/anthropics/claude-code/security/advisories/GHSA-jh7p-qr78-84p7).

### Reading a CI process environment

**Security research — Microsoft, 5 June 2026.** In a lab investigation of
Claude Code GitHub Action, Microsoft induced the agent's Read tool to access
`/proc/self/environ`, exposing `ANTHROPIC_API_KEY` despite subprocess
environment scrubbing. Microsoft reports that Anthropic mitigated the issue
in Claude Code 2.1.128 on 5 May. The demonstration shows why protecting one
execution path is insufficient when another tool can read the same data; it
does not establish losses suffered by victims.

Source: [Microsoft's technical analysis](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/).

### A poisoned package in an active coding session

**Investigated intrusion — Mandiant, September 2026 report.** Mandiant
describes an unnamed SaaS provider where an attacker hijacked an active
coding-assistant session. A developer accepted a recommendation to install a
poisoned Python package. The intrusion harvested GitHub OAuth tokens and
spread malware that stole repository secrets and proprietary source code.
The report does not name the assistant or give a financial-loss estimate.

This is an example of credential exposure through executed code. Encrypting
a local vault cannot protect values from malicious code that has the same
unlock access as the application.

Source: [Mandiant's AI Risk and Resilience 2026 report, case study 1](https://cloud.google.com/security/resources/ai-risk-and-resilience-2026).

### The wider exposure problem

GitGuardian's 2026 report counted **28.65 million new hardcoded secrets** in
public GitHub commits during 2025. It also found **24,008 unique secrets** in
MCP-related configuration files, including **2,117 unique valid credentials**.
These are findings from scanning, not counts of breaches or proof that AI
caused the exposures. They show that distributing credentials with
development configuration remains a substantial problem.

Source: [GitGuardian's State of Secrets Sprawl 2026](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/).

The cases illustrate failure paths that a development workflow should
consider. They do not establish that SourceOrrery would have prevented those
attacks, or that every coding agent inevitably leaks credentials.

## What changes in an everyday workflow

Consider a web application that needs `DATABASE_PASSWORD`. Its repository
can describe that requirement without holding the password:

```toml
# sourceorrery.toml
[project]
name = "my-app"
vault = "development"

[secrets.database-password]
env = "DATABASE_PASSWORD"
```

The corresponding reference is
`sourceorrery://development/database-password`. It identifies a secret;
it contains no credential value. Names, comments and other metadata still
need to be free of sensitive information.

With a development vault already created, the developer enters the value at
a hidden prompt, then launches the application:

```bash
sourceorrery secret set database-password --vault development
sourceorrery check
sourceorrery run -- npm start
```

The child process receives the declared value without changing the parent
shell's environment. Other parent environment variables are inherited,
except SourceOrrery's passphrase and passphrase-file variables. The child and
its dependencies can read or disclose the injected value, so this remains a
command for running trusted application code.

That gives three useful day-to-day patterns:

- **Refactoring with an agent:** share the manifest and metadata so the
  agent can edit configuration and report missing requirements. Enter values
  yourself. This reduces unnecessary exposure during cooperative work;
  it does not stop an agent with unlock access from retrieving a value.
- **Onboarding a teammate:** commit the same manifest and let each developer
  provision their own local vault and development credentials. The repository
  documents what is needed without distributing a shared password file.
- **Replacing a credential:** obtain a replacement from the service, store a
  new secret version, and restart the application or retrieve it again through
  an SDK. Updating a vault does not revoke the provider's old credential or
  change a value already delivered to a running process.

The [getting started guide](../site/src/content/docs/getting-started.mdx) walks
through setup. Existing applications can use
[`sourceorrery import .env`](cli.md#import-moving-a-env-file-into-a-vault);
the importer leaves the original file in place for you to review and remove
when ready.

## Why these design choices

| Choice in 0.1.4 | Reason |
| --- | --- |
| Encrypted local vault | Keep stored credential values out of plaintext project files, without requiring a cloud account or hosted service. |
| OS credential store or passphrase protection | Protect the vault key rather than placing an unprotected key beside the encrypted data. |
| References and a manifest | Make application requirements reviewable and version-controlled without embedding values. |
| Metadata by default | Inspect names, versions and status without printing credentials; revealing a value is explicit. |
| Versioning, time windows, recovery and audit | Manage changes and investigate use with more context than a copied configuration file provides. |
| One Rust core and read-only SDKs | Keep retrieval behaviour consistent across supported languages and keep mutation out of the application-facing SDK API. |

These choices also work for development without AI. A mistaken commit, an
overly broad diagnostic and a compromised dependency do not require a model.
AI-assisted workflows make it especially useful to separate what a project
needs from the values used to run it.

## Where stronger controls are still needed

SourceOrrery 0.1.4 is a local secrets tool. It has not been independently
audited and should be used with development credentials, rather than treated
as a production secret store. A program that can unlock the vault can read
its secrets. A read-only SDK, a manifest and agent instructions do not change
that boundary.

When an agent must be unable to obtain a credential, that restriction needs
to be enforced outside the agent: separate execution privileges, isolation,
and an authenticated service that authorises the operations it may perform.
Network restrictions, narrowly scoped credentials, provider-side spending
limits and rapid revocation can further reduce the consequences of misuse.
The [planned broker](roadmap.md#milestone-3--local-broker-and-agent-isolation)
addresses part of this future architecture; it is not included in 0.1.4.

If a credential has already been exposed, revoke or replace it at its issuer.
Importing it into an encrypted vault does not remove copies from Git history,
logs or transcripts, or undo access that has already occurred.

Read the [threat model](threat-model.md) for the current guarantees, the
[architecture](architecture.md) for the implementation, or
[get started](../site/src/content/docs/getting-started.mdx) with a development vault.
