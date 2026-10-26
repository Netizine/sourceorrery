# 0.3.0 documentation and website review

Reviewed on 25 October 2026 against the `security-remediation` checkout,
starting at `e05bd7a528f230bd006dd34e54ec08b4e246a073`. The index and
tracked working tree were clean at the start. Existing untracked design
assets and the Milestone 3 plan were left untouched. This is a local
documentation and website validation record, separate from a security audit
or a published release.

## Changes

- Current guides describe schema 5, C ABI 2, contract 2, independent key
  wraps/view checks, vault-owned provider connections, explicit reads and
  provider capabilities. The supported-file guide replaces legacy migration
  instructions. Cryptographic domain labels remain distinct from schema
  and application version numbers.
- The architecture, roadmap, release instructions and security-review
  landing page describe the current implementation. Earlier reviews and
  ADR context remain identifiable history. The archived early review
  retains its original body. The changelog preserves dated releases and
  identifies 0.3.0 as the next release.
- Install routes start with Homebrew and WinGet, then prebuilt archives,
  Cargo and source builds. WinGet's catalog submission was still open at
  review time; Scoop and release downloads are documented alternatives.
- The diagram and 68 synthetic walkthrough pages reflect the current UI.
  The site version comes from the workspace. Public prose uses maintainer
  voice, with LinkedIn alongside GitHub. Internal ownership records retain
  their required attribution.
- Optional Clarity analytics load only after permission. Advertising
  consent is denied. Refusal, browser privacy signals, unavailable storage
  and JavaScript-disabled visits leave the collector unloaded. Revocation
  stops it and reloads open tabs. The footer reopens privacy choices.
- Theme selection remains usable when browser storage is denied, including
  this-page changes and following the system theme in Auto mode.

## Validation performed

| Check | Result |
|-------|--------|
| Release Python helper suite | 66 passed. Expected rejection diagnostics and Python resource warnings from mocked HTTP failures did not fail the suite. |
| CI Python helper suite | 25 passed, including expected invalid-input refusals. |
| CLI agent integration suite, one Cargo job and one test thread | 9 passed; embedded installation references regenerated and drift checked. |
| Website Node tests | 26 passed: documentation tooling, consent and theme preferences. |
| Astro production build and link check | Passed; 47 pages, 4,142 internal references. Starlight reports an empty `i18n` collection warning. |
| Version checks | Package manifests and current guide stamps match 0.3.0; pages correctly identify it as unreleased. |
| CLI examples | 26 command/group help pages accepted. Synthetic create/set/list/get/update/versions, init/check/access, run, delete/recover, audit/export/import and reread passed. Child delivery omitted unlock variables. |
| Browser consent checks | Passed in isolated headless Edge. No choice/refusal produced no Clarity tag, queue or request. Acceptance queued analytics permission and advertising refusal before loading one mocked tag. Revocation reloaded both tabs without another request. GPC/DNT, denied storage and no JavaScript remained off. No page errors. |
| Visual and keyboard checks | Desktop light/dark and 320px banner screenshots inspected; equal consent actions remain available. Footer opening focuses the banner; Escape after a choice restores focus. Light/dark diagram screenshots inspected and every text box checked against its card and SVG bounds. |
| Repository Markdown targets | 343 checked; the only unresolved source-relative targets were 16 embedded skill references deliberately assembled into the installed layout. The generated layouts passed the integration drift test. |

All vault fixtures used disposable homes with the OS credential store
disabled. No real user vault or provider was opened. Browser requests were
intercepted and Clarity was mocked; no test visits were transmitted.
Local logs and screenshots are under `target/docs-review/` and are not
published assets.

The earlier completed UI validation remains recorded in
[UI implementation status](UI-IMPLEMENTATION-STATUS.md): 610 workspace
tests, 172 UI tests, formatting, Clippy and the minimal UI build passed
at that checkpoint. Those broader suites were not rerun for this
documentation/site change; no Rust implementation changed.

## Publication checks still to perform

Before deployment, inspect the Clarity project's Consent Mode, masking,
retention and access settings, then verify the deployed integration. This
review tested local consent gating with a mocked collector and did not
change the project's external settings.

Before releasing packages, run the exact candidate commit through full
hosted CI and a release dry run, then inspect the produced installers.
Trusted publishers are recorded as configured for the current packages;
the release guide distinguishes registry OIDC publishing from the existing
Maven signing/token and tag-based distribution paths. External account
settings were not independently audited here.

The [security review status](security-review.md) and
[UI record](UI-IMPLEMENTATION-STATUS.md) retain outstanding real-service,
platform, physical key-repeat/F2, screen-reader, authenticator-scanning and
first-use acceptance. The conditional path picker, asynchronous loading
and Milestone 3 remain deferred. No branch was pushed, release dispatched
or website deployed during this review.

## Package documentation follow-up

Package READMEs, registry descriptions and application API introductions
now direct readers to the [CLI installation guide](https://sourceorrery.ai/getting-started/#install).
The application SDKs are read-only; the CLI creates vaults and sets secret
values, while applications do not need a CLI process alongside them.
Installation choices and availability are maintained on the website rather
than repeated in registry pages. The npm release generator and embedded
agent references use the same link.

Validation checked 27 package/registry/archive README surfaces and all ten
SDK guide pages. Offline package listings included the README for all 11
publishable Cargo crates, and seven offline npm pack dry runs included the
updated README. All six native npm READMEs matched their generator.
Registry descriptions, README packaging paths and API documentation were
checked; executable code and public declarations were unchanged.

The 66 release-helper tests, nine integration tests (after regeneration,
with blessing disabled), 26 website tests, formatting and production site
build passed. All 4,142 internal references resolved. Fifty current guide
stamps and every package manifest matched 0.3.0. No package was published
and no branch was pushed by this follow-up.

## Agent setup and maintained skills

Forty-seven onboarding, SDK and package pages present manual CLI setup as
option 1 and AI-assisted setup as option 2. The agent route installs skills
with `sourceorrery init --integration all` (or one selected agent), then
lets the agent configure the manifest, application code and launch
commands. Vault creation, recovery keys and new values remain private user
steps. Installation copy uses the ready-install assumption; package
versions and publication history are unchanged.

Both skills and all their references were reviewed against the current
CLI and SDK interfaces. The maintained repository/plugin copies were
regenerated. They can be copied into projects independently of CLI package
updates; an installed CLI continues to write its own bundled snapshot.
The agent guide now explains that distinction and no longer suggests a
CLI rebuild for a skill-text update.

Corrections include explicit vault selection, unsupported-format guidance,
unknown provider-write outcomes, review before deleting imported files,
excluding tracked env files from code searches, and browser/edge/static
runtime limits. The public example manifest no longer uses the removed
per-secret vault field, and its walkthrough no longer prints injected
values.

Validation passed: nine integration tests with blessing disabled, three
skill metadata/layout tests, 66 release-helper tests and 26 website tests.
The production site built with 4,206 internal references resolving.
An isolated CLI check installed all twelve agent layouts without a vault,
manifest or usable recovery-key file, and a second run was unchanged.
Both documented search commands excluded root and nested tracked env
files in a key-name-only fixture. The corrected example parsed and reported
the expected unavailable-vault statuses. No real user vault or provider
was opened.

Desktop getting-started, agent-guide and SDK screenshots plus the 390px
layout were inspected. Browser requests were served from the local build;
there were no page errors or external requests. The optional skill-creator
Python helper could not run because PyYAML is unavailable; the repository's
metadata/layout checks passed, frontmatter was unchanged and installed
reference files resolved. No dependency was added, package release run or
branch push performed.

## LLM documentation publication

The website build now includes a concise `/llms.txt` index,
`/llms-full.txt` combining 24 essential references, a short product/setup
overview and clean Markdown companions for all 43 mirrored documentation
pages. The index covers the CLI, both agent skills, all twelve supported
agents, every SDK language, provider capabilities, operations and security
boundaries. Manual setup remains option 1 and AI-assisted setup option 2.
The CLI installation page remains the source for installation choices.

The text is generated from the same sources as the website, before its
MDX presentation conversion. Platform instructions and code examples are
preserved; presentation comments are removed and links are portable.
Version and release status come from the workspace and changelog. The
curated full text excludes historical ADRs and the optional roadmap.
Page headers advertise the index and each mirrored page's Markdown
companion. Azure Static Web Apps receives explicit Markdown/text MIME
types with the static deployment output. No new dependency was added.

Validation passed: 35 website tests, including nine text-generation
regressions; the production site build; all 4,861 internal HTML/Markdown
references; 50 documentation version checks; and package manifest version
checks. A local HTTP preview retrieved all 26 same-site index targets and
all 43 advertised companions, verified discovery on all 47 pages, and
checked coverage of twelve agents, nine SDK guides and three remote
provider mappings. The full file contains 24 distinct essential sources.
The current CLI's help confirmed the setup-selection and dry-run flags.
No real vault, provider or external analytics service was used.

The files are included in the normal site deployment; no separate package
release is needed. Live-domain/CDN retrieval and MIME headers await that
deployment. No branch was pushed and no site or package was published.
