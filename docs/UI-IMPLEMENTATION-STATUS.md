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
- Commits: `4265490`.
- Limitations/manual checks: live scanning with an authenticator and terminal-specific font behaviour unavailable. Rendering remains synchronous and presentation copies are not claimed to be zeroised.

### B05
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: `view/columns.rs`, `secrets.rs`, `lists.rs`, `projects.rs`, `view/mod.rs`, `viewport.rs`, `init/view.rs`, `view/tests.rs`. One selected specification drives headings/widths/cells; priority columns and grapheme-safe ellipses, actual table ranges, display-cell path/actor sizing. Version table responds to width.
- Tests and results: UI suite 143 passed, 1 ignored; 60/80/100/120/160-column tests, Unicode clipping, filtered counts and zero-read navigation regressions pass. Generated six-look snapshots and inspected selected rows.
- Commits: `851cc61`.
- Limitations/manual checks: B11 now passes full cached tags/path/actor/detail inspection and exact-return tests for clipped fields. Live-terminal checks unavailable.

### B06
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: `app.rs`, `view/mod.rs`, `view/overview.rs`, `view/tests.rs`, `snapshot.rs`. Responsive tabs retain the active view, header prioritises vault/state, footer budgets complete hints. Compact overview stacks/scrolls audit/expiry before activity and retains summary/daily activity data. Wide layout retained.
- Tests and results: UI suite 143 passed, 1 ignored; all compact overview sections reachable at 80×24, resize/all tabs/read-only/zero-read matrix passes. Snapshot writer passed; visually inspected compact overview, help and forms as reconstructed terminal-cell PNGs.
- Commits: `851cc61`.
- Limitations/manual checks: F2 Actions hint arrives with B08. Native terminal and screen-reader checks unavailable.

### B07
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: `theme.rs`, selected/focused renderers, `view/tests.rs`, `snapshot.rs`. Readable selected foreground, distinct underlined focus, match/disabled roles, adjusted meaningful paper colours and callout titles; terminal/native/no-colour/indexed modes retained.
- Tests and results: UI suite 143 passed, 1 ignored. Actual RGB and indexed palette semantic combinations meet 4.5:1 target; reverse and no-colour contracts pass. Snapshot writer passed; six looks visually inspected in `target/ui-snapshots/codex-six-looks.png` and compact screens in `codex-compact-review.png` (generated/ignored output).
- Commits: `851cc61`.
- Limitations/manual checks: PNGs are reconstructions of Ratatui TestBackend cells, not live terminal screenshots. User-controlled terminal colours need manual checks; no universal contrast claim.

### B08
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: `menu.rs`, `view/menu.rs`, `app.rs`, `keys.rs`, `session.rs`, `fake.rs`, `view/mod.rs`, `view/secrets.rs`, tests. Flat F2 menu uses typed shortcut actions, cached pure availability, bounded scrolling, disabled reasons and execution revalidation. Footer/empty guidance reuse availability. Overview search explains the proper tabs. Capability evidence for an older version is captured only during explicit detail opening; existing live checks still run when starting/submitting a mutation.
- Tests and results: UI suite 146 passed, 1 ignored. Menu/key equivalence, fresh Enter, compact/resize/long reasons, read-only/empty states, stale target rejection and zero list/inspect/audit/capability calls during menu navigation pass. Existing blocked/provider and confirmation tests pass.
- Commits: `ee6bc65`.
- Limitations/manual checks: F2 physical availability in supported terminal emulators has not been manually checked. No write occurs from menu navigation.

### B09
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: new `filters.rs`; `search.rs`, `app.rs`, `menu.rs`, keys and metadata renderers. Facets compile to existing queries with cached counts; same-kind facet replaces its qualifier, typed same-kind OR semantics stay intact. Active queries remain visible; original UTF-8 ranges map case expansions safely; selected match styles remain readable. No upstream source copied.
- Tests and results: UI suite 155 passed, 1 ignored. Facet/text equivalence, combined/no-result/clear, existing expiry boundaries, Unicode/case-expansion/sanitisation reconstruction and no-extra-read checks pass. Six-look filter fixtures added to snapshot writer.
- Commits: cached browsing commit (hash recorded next update).
- Limitations/manual checks: raw advanced query remains available; tag facets omit keys containing whitespace because the existing grammar cannot represent them as one token. Live usability checks unavailable.

### B10
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: new `sort.rs`; `app.rs`, keys/menu and title indicator. Secrets name/updated/expiry, Audit timestamp ordering use typed values, deterministic identity tie-breaks, missing dates last in both directions. Default is source order (Secrets name ascending, Audit newest first); source records are not reordered.
- Tests and results: UI suite 155 passed, 1 ignored. Typed time/missing dates/equal updated values, source-order reset, selection survival and zero-read assertions pass; B01 refresh identity regressions remain passing. Sort snapshots added.
- Commits: cached browsing commit (hash recorded next update).
- Limitations/manual checks: sort is session-local. No persistent index cache or dependencies added.

### B11
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: new `inspection.rs`, `view/inspection.rs`; `app.rs`, menu/keys, `view/mod.rs`, tests/fake/snapshots. Explicit `i` cached inspector wraps and scrolls complete metadata while preserving the underlying view; `!` and Actions expose complete safe messages, with a persistent visible route on the callout. Full IDs remain distinct from displayed abbreviations.
- Tests and results: UI suite 155 passed, 1 ignored. Long tags, project/vault paths, Unicode audit actors and details, hostile controls, long errors, exact query/table/detail return state, zero/tiny areas and zero additional list/inspect/audit/capability reads pass. Inspector fixtures added to all six looks.
- Commits: cached browsing commit (hash recorded next update).
- Limitations/manual checks: cached inspection never fetches an absent field; explicit Enter retains the established audited detail load. Live terminal/screen-reader checks unavailable.

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
