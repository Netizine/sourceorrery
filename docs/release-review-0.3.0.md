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
