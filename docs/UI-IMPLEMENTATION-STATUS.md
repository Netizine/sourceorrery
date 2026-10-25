# UI implementation status

**Owner: James’s UI workstream — implemented with Codex.**

This record covers UI changes only; Claude owns the concurrent security remediation. No security work is claimed here.

## Initial checkout (25 October 2026)

- Branch: `security-remediation`; HEAD: `742f29d98cdce609748e5f2af0ba607364319493`.
- Staged changes: none.
- Unstaged changes: `.github/workflows/ci.yml`, `docs/building.md`.
- Untracked: `SourceOrrerySecureArchitecture.png`, `SourceOrrerySecureArchitecture.svg`, `docs/Milestone-3-Plan.md`, `docs/UI-enhancements.md`, `scripts/ci/feature-matrix.sh`, `sourceorrery-fontawesome.svg`.
- UI plan is supplied input, included with authorised ownership/status edits. Other initial files remain outside this workstream.
- Baseline: `cargo test -p sourceorrery-cli --locked ui::`: 127 passed, 1 intentionally ignored snapshot writer.
- Configured Git identity: James Melvin <james@netizine.com>.

## Batches

### B01
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: `ui/app.rs` preserves full vault/secret/version/project/audit identities through refresh/filter replacement, clears vanished targets, and rechecks typed confirmation targets from cached metadata; `ui/fake.rs` supports changing version sets.
- Tests and results: `cargo test -p sourceorrery-cli --locked ui::app::`: 40 passed. New regressions insert/remove versions, reorder/filter lists and reject a vanished confirmation target without reads. Existing provider, blocked, read-only, mutation and lock tests pass.
- Commits: `20db4f0`.
- Limitations/manual checks: confirmation checks current cached identity; mutations retain the source/editor’s own live checks. No real vaults or live-terminal checks performed. B01 was not already fixed in initial HEAD `742f29d`.

### B02
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: browser `keys.rs`, setup/init `mod.rs` require fresh Press for review/commit and one-shot transitions; movement/text repeats remain supported. Revalidated initial code; no existing remediation duplicated.
- Tests and results: UI suite 136 passed, 1 ignored; browser Press/Repeat/Repeat/Release/Press regression and both wizard key gates pass.
- Commits: `20db4f0`.
- Limitations/manual checks: Windows Terminal and non-Windows physical key-repeat checks unavailable; terminals reporting repeats as Press cannot be distinguished.

### B03
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: `app.rs`, `keys.rs`, `view/mod.rs`, `view/projects.rs`, new `viewport.rs`, `view/tests.rs`. Retained help viewport and declaration table, paging/home/end, persistent close hint and actual table ranges. Presentation reflow uses Ratatui graphemes and exact rendered rows.
- Tests and results: UI suite 136 passed, 1 ignored. New TestBackend checks reach all help sections at 80×24/60×18, all 50 project declarations at 80×24, restore project selection and assert zero extra reads; Unicode reflow test passes.
- Commits: `20db4f0`.
- Limitations/manual checks: live terminal and screen-reader checks unavailable. No upstream source copied.

### B04
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: browser `app.rs`, `keys.rs`, `view/dialog.rs`; setup/init `mod.rs`, `view.rs`, `wizard.rs`; shared `viewport.rs` and three test modules. Fixed title/control areas, focus-following and manual review/error scrolling; exact shared word/grapheme reflow; compact step rails; QR rendered only when it fits whole, with manual enrolment key preserved. Secret buffers remain in their original owners.
- Tests and results: `cargo test -p sourceorrery-cli --locked ui::`: 139 passed, 1 ignored. New compact form/review/long-error/resize tests and 80×24/60×18 authenticator fallback tests pass; existing secret redaction, validation, cancel and commit tests pass.
- Commits: B04 bounded-forms commit (hash recorded next update).
- Limitations/manual checks: live scanning with an authenticator and terminal-specific font behaviour unavailable. Rendering remains synchronous and presentation copies are not claimed to be zeroised.

### B05
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B06
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B07
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B08
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B09
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B10
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B11
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B12
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B13
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B14
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B15
- Owner: James’s UI workstream — implemented with Codex.
- Status: Planned
- Changes and affected files: pending.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

### B16
- Owner: James’s UI workstream — implemented with Codex.
- Status: Deferred
- Changes: conditional path picker deferred as requested.
- Tests and results: not run for this batch.
- Commits: pending.
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

## Deferred architecture

Asynchronous/paged loading and Milestone 3 remain deferred. No dependencies or upstream source are added.
