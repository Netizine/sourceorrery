# UI implementation status

**Owner: James’s UI workstream — implemented with Codex.**

This record covers UI changes only; Claude owns the concurrent security remediation. No security work is claimed here.

**B01–B15 code is implemented.** B02 and B08 await physical-terminal acceptance; they are not marked Done. The other batches have passed their applicable automated and snapshot checks. Final validation uses one Cargo job at a time. Claude’s security remediation remains outside this ownership record.

Paths under `ui/` below refer to `crates/sourceorrery-cli/src/ui/`.

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
- Status: Blocked — physical-terminal acceptance pending; implementation and automated checks complete.
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
- Status: Blocked — physical-terminal acceptance pending; implementation and automated checks complete.
- Changes and affected files: `menu.rs`, `view/menu.rs`, `app.rs`, `keys.rs`, `session.rs`, `fake.rs`, `view/mod.rs`, `view/secrets.rs`, tests. Flat F2 menu uses typed shortcut actions, cached pure availability, bounded scrolling, disabled reasons and execution revalidation. Footer/empty guidance reuse availability. Overview search explains the proper tabs. Capability evidence for an older version is captured only during explicit detail opening; existing live checks still run when starting/submitting a mutation.
- Tests and results: UI suite 146 passed, 1 ignored. Menu/key equivalence, fresh Enter, compact/resize/long reasons, read-only/empty states, stale target rejection and zero list/inspect/audit/capability calls during menu navigation pass. Existing blocked/provider and confirmation tests pass.
- Commits: `ee6bc65`.
- Limitations/manual checks: F2 physical availability in supported terminal emulators has not been manually checked. No write occurs from menu navigation.

### B09
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: new `filters.rs`; `search.rs`, `app.rs`, `menu.rs`, keys and metadata renderers. Facets compile to existing queries with cached counts; same-kind facet replaces its qualifier, typed same-kind OR semantics stay intact. Active queries remain visible; original UTF-8 ranges map case expansions safely; selected match styles remain readable. No upstream source copied.
- Tests and results: UI suite 155 passed, 1 ignored. Facet/text equivalence, combined/no-result/clear, existing expiry boundaries, Unicode/case-expansion/sanitisation reconstruction and no-extra-read checks pass. Six-look filter fixtures added to snapshot writer.
- Commits: `f913ffe`.
- Limitations/manual checks: raw advanced query remains available; tag facets omit keys containing whitespace because the existing grammar cannot represent them as one token. Live usability checks unavailable.

### B10
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: new `sort.rs`; `app.rs`, keys/menu and title indicator. Secrets name/updated/expiry, Audit timestamp ordering use typed values, deterministic identity tie-breaks, missing dates last in both directions. Default is source order (Secrets name ascending, Audit newest first); source records are not reordered.
- Tests and results: UI suite 155 passed, 1 ignored. Typed time/missing dates/equal updated values, source-order reset, selection survival and zero-read assertions pass; B01 refresh identity regressions remain passing. Sort snapshots added.
- Commits: `f913ffe`.
- Limitations/manual checks: sort is session-local. No persistent index cache or dependencies added.

### B11
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: new `inspection.rs`, `view/inspection.rs`; `app.rs`, menu/keys, `view/mod.rs`, tests/fake/snapshots. Explicit `i` cached inspector wraps and scrolls complete metadata while preserving the underlying view; `!` and Actions expose complete safe messages, with a persistent visible route on the callout. Full IDs remain distinct from displayed abbreviations.
- Tests and results: UI suite 155 passed, 1 ignored. Long tags, project/vault paths, Unicode audit actors and details, hostile controls, long errors, exact query/table/detail return state, zero/tiny areas and zero additional list/inspect/audit/capability reads pass. Inspector fixtures added to all six looks.
- Commits: `f913ffe`.
- Limitations/manual checks: cached inspection never fetches an absent field; explicit Enter retains the established audited detail load. Live terminal/screen-reader checks unavailable.

### B12
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: new `text_input.rs`; `edit.rs`, app/keys/dialog, setup/init wizard/key/view modules and tests, `viewport.rs`, snapshots. Cursor and horizontal window for metadata and explicitly non-secret wizard fields (including manifest path); Left/Right/Home/End/Delete/Backspace use UTF-8/grapheme boundaries. Combining clusters are single editing units. Focus returns on editing/resize. Hidden value/password/recovery/credential buffers retain their owners and append/pop paths.
- Tests and results: UI suite 160 passed, 1 ignored. Start/middle/suffix edits, CJK/combining deletion, horizontal cursor/resize, wizard path/hint editing, command isolation, hidden-buffer length/redaction/cancel clearing and existing secret-state tests pass. Cursor snapshot fixture added.
- Commits: `22877be`.
- Limitations/manual checks: paste support is not introduced; native value prompts unchanged. Live terminal cursor/font behaviour unavailable.

### B13
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: `feedback.rs`, `app.rs`, `ui/mod.rs`, `view/mod.rs`, fake/tests/snapshots. Explicit successful-load time, persistent refresh failures and provider warnings, pre-operation synchronous draw and elapsed-operation feedback. Failed secondary reads still restore inactive-tab identities; failed detail refresh clears the version target. Repeated refresh retains pending lazy-tab selection. Errors remain until acknowledged or superseded.
- Tests and results: Final targeted UI suite: 172 passed, 1 intentionally ignored snapshot writer. Primary/secondary/detail failure, provider partial-load warning, slow synthetic operation (at least 2ms), exact call-count/no-retry, selection identity and error acknowledgment tests pass. Feedback snapshots visually inspected.
- Commits: `7564edb`.
- Limitations/manual checks: synchronous work still blocks input and locking until it returns; the UI explicitly says so. No real-provider timing measurements or live-terminal checks performed. Asynchronous loading remains deferred.

### B14
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: `app.rs`, `menu.rs`, `keys.rs`, `theme.rs`, `ui/mod.rs`, `view/mod.rs`, tests/snapshots. Session-local Dark/Light/Terminal preview; Enter applies, Esc/quit/idle-lock restores the exact prior choice and changed flag. Applied themes reach child setup screens; captured NO_COLOR/indexed capabilities are retained.
- Tests and results: Final UI suite: 172 passed, 1 ignored. Preview/cancel/immediate Enter/quit/resize/NO_COLOR/indexed capabilities/child-screen palette/idle-lock and zero-read assertions pass. Theme preview snapshots visually inspected in colour and no-colour looks.
- Commits: `7564edb`.
- Limitations/manual checks: no persistent theme preference or theme files. Actual terminal palette/font behaviour and screen-reader use remain unverified.

### B15
- Owner: James’s UI workstream — implemented with Codex.
- Status: Done — James’s UI workstream (implemented with Codex).
- Changes and affected files: `app.rs`, `ui/mod.rs`, `view/mod.rs`, tests/snapshots. Existing Instant inactivity clock drives bounded one-second polls and a last-30-seconds header warning above transient overlays. Lock drops session ownership and clears pending requests/value workflows, dialogs, menus, inspection, help, selection/viewport state and feedback.
- Tests and results: Final UI suite: 172 passed, 1 ignored. Deterministic elapsed-clock boundaries and rounding, quiet pre-warning window, transient-state clearing, released session ownership and zero extra reads pass. Warning/preview/compact snapshots inspected. Ticks never reset last-key activity.
- Commits: `7564edb`.
- Limitations/manual checks: warning cannot tick during an existing synchronous operation. No live-terminal timeout or screen-reader checks performed.

### B16
- Owner: James’s UI workstream — implemented with Codex.
- Status: Deferred
- Changes and affected files: none; conditional path picker deferred as requested.
- Tests and results: not run for this batch.
- Commits: none (deferred).
- Limitations/manual checks: live terminal, non-Windows terminal and screen-reader checks have not been performed.

## Deferred architecture

Asynchronous/paged loading and Milestone 3 remain deferred. No dependencies or upstream source are added.

## Final validation and manual acceptance

- `cargo test -p sourceorrery-cli --locked -j 1 ui:: -- --test-threads=1`: **172 passed, 0 failed, 1 intentionally ignored** snapshot writer.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --all-targets --locked -j 1 -- -D warnings`: passed.
- `cargo check -p sourceorrery-cli --no-default-features --features ui --locked -j 1`: passed.
- `cargo test --workspace --locked -j 1 -- --test-threads=1`: **610 passed, 0 failed, 1 intentionally ignored** across 40 unit/integration/doc-test groups. This final run includes the three follow-up failure/provider regressions.
- Explicit snapshot writer passed: **384 synthetic screens plus the index**, six looks. Visually inspected ten reconstructed terminal-cell contact sheets covering selected enabled/disabled/expired rows, search matches, menus, filters, cached inspection, focused text, refresh/error feedback, theme preview, idle warning and compact overview/help. Generated output is ignored under `target/ui-snapshots/`; these are TestBackend reconstructions, not native terminal screenshots.
- All fixtures use fake sources/editors or temporary synthetic vaults with NoStore. No real user vaults or live providers opened. No dependencies or upstream code added.
- Final UI-only lint adjustments in `app.rs`, `keys.rs`, `session.rs`, `text_input.rs`, setup/init wizard constructors and secret-column/row presentation keep the repository’s Clippy checks passing; no repository-wide formatting was performed.
- **Required manual terminal acceptance is outstanding for B02 (physical key-repeat/one-write behaviour in Windows Terminal and a non-Windows terminal) and B08 (F2 availability).** Their implementations and automated acceptance checks are complete; status remains Blocked until those manual checks are performed.
- First-time-user tasks in the plan, a basic terminal screen-reader check, live authenticator scanning and native font/colour/cursor checks have not been performed. No usability/adoption or universal terminal-contrast claim is made.

## Pause and resume history — 25 October 2026

The user paused work because the machine was nearly hanging, then explicitly requested continuation. Codex stopped only its own build process trees during the pause. Interrupted validation had no pass/fail result and is superseded by the completed checks above.

The saved checkpoint was `22877befd5806036b6543ec7cf068160eb969e58`, with an empty index and B13–B15 uncommitted. On resume, every saved UI source hash matched; Claude’s later commits through `14b6f3e` had no UI-file overlap. Security/storage/CI/changelog/security documentation and unrelated artwork/Milestone-3 files were preserved. Validation resumed serially with `CARGO_BUILD_JOBS=1` and one test thread.

The historical resume memory is `C:/Users/JamesMelvin/.codex/memories/sourceorrery-ui-resume.md`. Its adjacent review-only WIP patch is an obsolete checkpoint and must not be applied over the completed implementation.
