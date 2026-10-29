# Documentation for SourceOrrery 0.3.1

The current guides describe the 0.3.1 source tree: vault schema 5, C ABI 2
and contract 2. Release availability comes from the dated changelog and
the release workflow; source documentation can precede publication.

Start with the [first-run guide](getting-started.md), [CLI reference](cli.md)
or [application SDK guides](sdks/index.md). The [architecture](architecture.md),
[provider mappings](providers/index.md) and [vault format](vault-format.md)
explain the implementation. [Supported files, export and import](upgrading.md)
covers portability without a legacy conversion workflow.

[Why SourceOrrery?](why-sourceorrery.md) explains the project's goals;
[Why the name SourceOrrery?](why-the-name-sourceorrery.md) tells the story
of orreries, Tolkien and the engineering ideas behind the name.

The website's install page puts Homebrew and WinGet before manual downloads,
Cargo and source builds. Website analytics are optional and covered by the
[privacy page](privacy.md); they are not part of the CLI or SDKs.

## Setup options

1. **Option 1: Set up with the CLI.** Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install),
   then create the vault and set its secret values in your own terminal.
2. **Option 2: Set up with an AI coding agent.** Run
   `sourceorrery init --integration all`, then ask your agent to set up
   SourceOrrery for the project without showing values. You keep vault
   keys and new values private. [The agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
   works with an existing CLI installation.

## Current guidance and historical records

The [roadmap](roadmap.md) separates implemented features from future work.
The [security review status](security-review.md), [supply-chain guide](supply-chain.md)
and [release procedure](release.md) describe the evidence and release checks.
The [documentation and website review of 25 October](release-review-2026-10-25.md)
records the local checks, visual inspection and publication checks it left
to perform.

ADRs retain design history and carry supersession notes where the
implementation changed. Dated security reviews, Sonar reports and the
[remediation validation ledger](security-remediation-validation.md) are
evidence at their stated commits, not current command tutorials. The
[archived early review](security-review-archive-2026-10.md) predates the
current key and connection model.

The [UI implementation record](UI-IMPLEMENTATION-STATUS.md) and
[UI enhancement specification](UI-enhancements.md) are workstream records.
They retain their required ownership and acceptance status. The conditional
path picker, asynchronous loading and Milestone 3 remain deferred.

## Maintaining these pages

Edit the Markdown in `docs/`. `site/scripts/sync-docs.mjs` generates its
website copies; the homepage and install page are authored MDX under
`site/src/content/docs/`. The architecture PNG and synthetic walkthroughs
are maintained with the site sources. [Site development](../site/README.md)
covers building and checking them.

After a version change, run `python scripts/release/docs-version.py` and
its `--check` mode. Review the diagram and command examples against the
implementation as well: stamping a version does not validate behaviour.
