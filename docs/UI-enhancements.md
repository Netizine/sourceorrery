# SourceOrrery UI enhancements

**Review date:** 25 October 2026  
**Scope:** Ratatui browser, setup and init wizards; the six requested upstream references; existing UI snapshots.  
**Review status:** Original recommendations and implementation specification. See the implementation record below for delivered code, checks and outstanding acceptance.

> **Implementation ownership:** James’s UI workstream — implemented with Codex.
> See [UI implementation status](UI-IMPLEMENTATION-STATUS.md) for batch ownership, validation, commits and limitations. B01–B15 code is implemented; B02/B08 await physical-terminal acceptance. B16, asynchronous loading and Milestone 3 remain deferred. The review below is the original implementation specification.

## Recommendation

Keep SourceOrrery's warm paper appearance, restrained rules, typography hierarchy and metadata-only browser. The current UI already looks coherent. The biggest gains will come from making every screen usable in an ordinary terminal, making actions discoverable, and making selection, focus and feedback more reliable.

A polished first increment should deliver:

1. Stable selection and deliberate confirmation.
2. Reachable help, project details and forms at 80×24.
3. Responsive columns, tabs, footer and overview.
4. Stronger selected-row contrast.
5. A small contextual **Actions** menu and discoverable filters.

These changes can use the existing Ratatui dependency and standard Rust. Do not add Chamber, Taskui, ratagrid, tui-menu, ratatui-explorer or Opaline as dependencies. Borrow their interaction ideas selectively; preserve SourceOrrery's existing state, source and editor boundaries.

Milestone 3 is outside this work. None of these recommendations needs a local broker or agent isolation.

## Review basis and limitations

The local checkout reported commit **b75ba836215d356b0e42b55246c8ab618003b90b** during review. Security remediation was happening concurrently. Recheck these findings against the completed remediation before implementation, especially U01 and U02. File/function names below are the more durable anchors; cited line numbers describe this review's checkout.

The snapshot directory contained **277 HTML files**, including the index: 46 states in six looks. The state files comprise 270 screens at 120 columns and six authenticator screens at 80 columns. Heights vary by fixture; notably, help is given 46 rows. The files inspected were generated around 06:55 on 25 October and may predate changes in the working tree.

I inspected the saved snapshot text, colour styles and generating code, and visually reviewed 13 representative static terminal-cell reconstructions: dark/light/no-colour secrets, overview, secret detail, project detail, help, search, metadata edit, error, setup review, provider connections and the 80×24 authenticator view. These were reconstructed from the saved text/style runs without executing HTML. They are not live-terminal or browser screenshots; font fallback and terminal-specific behaviour still need manual validation.

Upstream source was read at the pinned revisions below. Upstream applications were not executed. No real vault was opened, no application tests were run, and snapshots were not regenerated for this documentation-only review.

### What is already working well

- Search already supports words and metadata qualifiers, including status, tags, content type and expiry. Audit search has its own qualifiers.
- Contextual key hints, help, counts, empty states, no-match guidance, confirmation dialogs, a vault selector and idle locking already exist.
- The browser caches metadata. Moving, filtering and drawing do not need repeated vault/provider reads.
- Secret details already show versions and activity. There is no need to invent a second complete detail system.
- Dark, light, terminal-native, indexed-colour and no-colour behaviour are already considered.
- Setup has a step rail, review before commit, masked credential fields, password guidance and an authenticator layout specifically represented at 80×24.
- The separation of application state, keys, session, source, editor and views is worth retaining.

## What to take from the referenced projects

These are design/source references, not endorsements of their complete architecture or security model.

| Reference and reviewed revision | Useful ideas for SourceOrrery | What to leave behind |
| --- | --- | --- |
| [Chamber — 77edf89435e4](https://github.com/mikeleppane/chamber/tree/77edf89435e481b45412d45ff9d042335c39d2ae) · [MIT](https://github.com/mikeleppane/chamber/blob/77edf89435e481b45412d45ff9d042335c39d2ae/LICENSE) | Visible filter categories/counts, search-match highlighting, scroll position and context-sensitive hints. Its [category view](https://github.com/mikeleppane/chamber/blob/77edf89435e481b45412d45ff9d042335c39d2ae/crates/ui/src/ui.rs#L1197) is a useful discovery pattern. | Fixed three-column proportions, large central UI modules, emoji-dependent categories, value search, reveal and clipboard flows. SourceOrrery filters metadata only. |
| [Taskui — e0912f28e32f](https://github.com/thmshmm/taskui/tree/e0912f28e32f2b8798befbec24a23d72fd698b6d) · [MIT](https://github.com/thmshmm/taskui/blob/e0912f28e32f2b8798befbec24a23d72fd698b6d/LICENSE) | Compact screen composition and an explicit [preview mode](https://github.com/thmshmm/taskui/blob/e0912f28e32f2b8798befbec24a23d72fd698b6d/src/taskui/ui.rs#L59) that retains list context. | Command execution and simpler search semantics. Keep SourceOrrery's existing qualifier search and Esc conventions. |
| [ratagrid — e2fee5f2cf47](https://github.com/kahwee/ratagrid/tree/e2fee5f2cf47400f9aa3306717777ba2484b4779) · [MIT](https://github.com/kahwee/ratagrid/blob/e2fee5f2cf47400f9aa3306717777ba2484b4779/LICENSE) | [Stable row identity and typed sorting](https://github.com/kahwee/ratagrid/blob/e2fee5f2cf47400f9aa3306717777ba2484b4779/src/model.rs#L157), a separate visible row order and deliberate column visibility. | A generic grid framework, drag/reorder, pagination infrastructure and its extra dependency/toolchain requirements. The reviewed manifest specifies Rust 1.99. |
| [tui-menu — c692c1aa2a5d](https://github.com/shuoli84/tui-menu/tree/c692c1aa2a5dc26bbcdd6ac9e9c4d496c58e0768) · [MIT OR Apache-2.0](https://github.com/shuoli84/tui-menu/blob/c692c1aa2a5dc26bbcdd6ac9e9c4d496c58e0768/Cargo.toml) | [Typed menu items and selection events](https://github.com/shuoli84/tui-menu/blob/c692c1aa2a5dc26bbcdd6ac9e9c4d496c58e0768/src/lib.rs#L314): moving through a menu is separate from executing a selected action. | Arbitrarily nested menus and a copied low-level popup renderer. A flat, bounded Ratatui List is sufficient. |
| [ratatui-explorer — c518bdf465be](https://github.com/tatounee/ratatui-explorer/tree/c518bdf465be9b3e57282809826a84322338aeb4) · [MIT](https://github.com/tatounee/ratatui-explorer/blob/c518bdf465be9b3e57282809826a84322338aeb4/LICENCE.txt) | Explicit directory state, parent navigation and directories-first ordering, if an existing path-entry workflow needs a picker. See [directory enumeration](https://github.com/tatounee/ratatui-explorer/blob/c518bdf465be9b3e57282809826a84322338aeb4/src/file_explorer.rs#L662). | A general file manager, content previews, recursive discovery or automatic import. Several empty-list/error assumptions need improving rather than copying. |
| [Opaline 0.4.2 — c9edc3df2539](https://github.com/hyperb1iss/opaline/tree/c9edc3df25396f0688e789c73e8ec3019fd52b5e) · [MIT](https://github.com/hyperb1iss/opaline/blob/c9edc3df25396f0688e789c73e8ec3019fd52b5e/LICENSE) | Semantic palette/style separation, [theme contract tests](https://github.com/hyperb1iss/opaline/blob/c9edc3df25396f0688e789c73e8ec3019fd52b5e/tests/builtins_tests.rs#L139), and reversible live preview. | A token resolver, string-keyed style engine, global singleton, user theme discovery, many imported palettes or gradients. SourceOrrery already has a typed Theme. |

### Adaptation and attribution

Prefer a fresh implementation of the small behaviour inside SourceOrrery's existing abstractions. If actual source is copied or substantially adapted, preserve the upstream copyright/licence notices and record the repository, pinned revision, original file and local destination in an attribution note. Rewriting names or moving code does not remove the notice requirement. No upstream code has been copied into the application by this review.

Specific upstream details **not** to transplant:

- Chamber's [search highlighting](https://github.com/mikeleppane/chamber/blob/77edf89435e481b45412d45ff9d042335c39d2ae/crates/ui/src/ui.rs#L1144) uses lowercased matching offsets. Do not apply offsets from a case-converted string directly to the original UTF-8 text: case conversion can change length.
- tui-menu's [popup renderer](https://github.com/shuoli84/tui-menu/blob/c692c1aa2a5dc26bbcdd6ac9e9c4d496c58e0768/src/lib.rs#L592) constrains its rectangle but still iterates groups using its original coordinates. Use a real viewport with scrolling.
- ratatui-explorer's [navigation](https://github.com/tatounee/ratatui-explorer/blob/c518bdf465be9b3e57282809826a84322338aeb4/src/file_explorer.rs#L199) contains empty-list indexing assumptions and removes a selected entry before navigation can fail. Use optional selection and replace directory state only after successful enumeration.
- Opaline's global state and style-merging rules are unnecessary here. Keep explicit Theme ownership and SourceOrrery's reverse-selection handling.

## Prioritised changes and exact implementation seams

**Priority terms:** “Correctness” means a source-confirmed interaction problem; “Core polish” means the recommended next UI increment; “Optional” means defer until the core work is satisfactory. These are UI priorities, not a replacement security severity assessment.

All file links resolve from this document to the existing repository. Proposed new files are identified explicitly.

### U01 — Keep the same selected object after refresh, filtering and sorting

**Priority:** Correctness. **Effort:** Medium. **Inspiration:** ratagrid.

**Evidence:** [App::reread][app], around lines 695–723, saves and restores a numeric version index. If another process inserts a newer version, that index points at another version. **target_version**, around lines 754–766, subsequently resolves the currently indexed item. A stable-looking highlight can therefore refer to a different mutation target. List selection also needs an explicit identity policy.

**Change:**

- Capture the selected version's full ID before reload, then locate that same ID after reload.
- Apply stable keys to list views: vault identity plus secret name; full version ID; project link ID; audit event ID; and vault identity.
- Keep TableState for viewport mechanics, but do not use its row number as object identity across dataset replacement.
- When a selected object disappears, clear it and show a brief explanation. Avoid silently making the next destructive action target a neighbour.
- Remove the **selected().unwrap_or(0)** fallback in **target_version()** when no version is selected. Ensure **clamp()** does not immediately recreate a deliberately cleared selection; absent selection must mean there is no mutation target.
- For an intentional filter change, define the behaviour explicitly: preserve a surviving selection; otherwise leave selection empty until the user navigates. Initial opening may still select the first row.
- Confirmation should carry a typed target identity, and execution should recheck that it is still available.

**Files:** [app.rs][app] — ListState, shown_*(), selected_*(), reread(), clamp(), target_version(); [edit.rs][edit] — confirmation target; [session.rs][session] only where refreshed identity lookup needs support.

**Tests / acceptance:** Insert a newer version, remove the selected version, reorder a list and shrink a filter. A surviving selection stays on the same object; after removal, invoking Edit/Toggle must not target another version. Existing confirmations still apply. Sorting/filtering alone makes zero source calls.

### U02 — Make review and commit require deliberate key presses

**Priority:** Correctness; coordinate with security remediation. **Effort:** Small.

**Evidence:** [keys.rs][keys], lines 12–15, ignores Release but accepts Repeat. Enter in a dialog maps to Commit. [App::update_dialog][app], around lines 979–1012, can turn the first Commit into review and the next into a write. Setup and init key handlers have the same release-only filtering policy.

**Change:** Treat navigation and text repeat separately from consequential actions. Accept a fresh Press for review, commit, menu execution and other one-shot transitions; ignore Repeat for these actions. Continue allowing repeat where it helps movement and editing. Do not require Release events on terminals that do not report them.

**Files:** [keys.rs][keys], [app.rs][app], [setup/mod.rs][setup-mod], [init/mod.rs][init-mod], their key/wizard tests.

**Tests / acceptance:** For Press → Repeat → Repeat → Release → Press, no write occurs before the second fresh press, and at most one write occurs afterwards. Navigation still repeats. Manually check Windows Terminal and at least one non-Windows terminal; some terminals report auto-repeat as ordinary presses, so do not claim universal physical-key detection from this change alone.

### U03 — Make help usable at 80×24

**Priority:** Correctness and Core polish. **Effort:** Small.

**Evidence:** [draw_help()][view], lines 622–689, renders roughly 40 content lines without scrolling or wrapping. [Mode::Help][keys] ignores movement. The 46-row help snapshot conceals this limitation.

**Change:**

- Introduce retained HelpState with scroll position; use bounded Paragraph/List content with wrapping and a persistent close hint.
- Support Up/Down, PgUp/PgDn, Home/End and Esc.
- Lead with actions for the current view, then general navigation, search examples and audit behaviour.
- Keep complete help reachable; do not remove the useful explanation of what reads the vault.
- At narrow widths, stack key and description when the fixed key column leaves too little room.

**Files:** [app.rs][app] — help state/mode; [keys.rs][keys]; [view/mod.rs][view] — draw_help(); [view/tests.rs][view-tests]; [snapshot.rs][snapshots].

**Tests / acceptance:** At 80×24 and 60×18, every section can be reached and Esc is always visible. Resizing preserves a valid scroll position. Opening and scrolling help makes no metadata calls.

### U04 — Scroll through every project's declared secrets

**Priority:** Correctness. **Effort:** Small.

**Evidence:** [projects::detail()][projects], lines 134–220, passes a new TableState on each draw and makes the declarations table unselectable. [App::move_by][app], around lines 520–543, treats detail movement as secret-version navigation. A large manifest's declarations below the viewport cannot be reached.

**Change:** Give project detail its own retained table/scroll state, correct page height and Up/Down/PgUp/PgDn/Home/End routing. Display the visible range. Merely highlighting a declaration must not resolve or read a secret. An explicit “open secret details” action can be considered separately.

**Files:** [app.rs][app], [view/projects.rs][projects], [view/mod.rs][view] — page/state routing and hints.

**Tests / acceptance:** A 50-secret project is completely inspectable at 80×24. Empty, missing and unreadable manifests remain clear. Esc restores the project list and its selection. Scrolling reads neither values nor provider metadata.

### U05 — Keep fields, errors and confirmation controls on screen

**Priority:** Correctness and Core polish. **Effort:** Medium.

**Evidence:** [dialog::draw()][dialogs], lines 19–50, calculates a desired size and lets the layout constrain it, but has no viewport or scroll state. Long metadata/errors and small terminals can hide the active field or confirmation text. Setup/init already try to follow focus, but their **scroll_for()** functions estimate wrapping by dividing display width; word wrapping can consume more rows than this estimate.

**Change:**

- Reserve a small fixed area for title and action hints; give content the remaining scrollable area.
- Follow focus, show overflow/position, and permit manual scrolling of long review/error content.
- Share a small presentation helper for measured wrapped content and focus visibility. Match the actual wrapping policy used by the widget; do not keep a separate approximate character-count formula.
- Keep an error's actionable portion visible beside the relevant field; allow full details to be opened.
- For short screens, use compact labels and a step indicator such as “Step 3 of 6 — View check” in place of a clipped full rail.
- Preserve manual authenticator-key entry if a complete QR layout cannot fit. Do not display a clipped QR code as though it were scannable.
- Preserve existing typed secret-state ownership and clearing behaviour; avoid introducing persistent copies of sensitive text. Do not assume all rendered setup text is zeroised.

**Files:** [view/dialog.rs][dialogs], [edit.rs][edit], [setup/view.rs][setup-view], [setup/wizard.rs][setup-wizard], [init/view.rs][init-view], [init/wizard.rs][init-wizard]. A private **ui/view/viewport.rs** may hold presentation-only helpers.

**Tests / acceptance:** At 80×24 and 60×18, the last focused field, full confirmation target, error route and cancel/confirm controls remain reachable with long tags, paths and word-heavy errors. Resize while the last field is active. Test the 80×24 QR flow, short-screen fallback, validation failure and cancel. No hidden commit on focus movement.

### U06 — Responsive tables, overview and navigation chrome

**Priority:** Core polish. **Effort:** Medium–large; split into two batches.

**Evidence:** The secrets snapshot truncates tags without an obvious overflow indicator even at 120 columns. [secrets::list()][secrets] requests eight columns, including two 16-cell timestamps. The overview always divides its rows into multiple panels ([overview.rs][overview], lines 35–134). The tab bar always emits all six tabs. The footer drops its reassurance text when space runs out but still emits all action hints, which can themselves be clipped.

**Change:**

- Define a small layout profile from the available content width and height, not a universal fixed terminal size.
- Generate headings, widths and row cells from the same chosen column specification.
- Reserve name and status first. Show expiry/storage when space permits; leave versions, projects and tags in the existing explicit detail view when they do not fit.
- Show a visible overflow cue for clipped metadata and a reliable route to its complete representation. Do not use an abbreviated identifier as an action target.
- Add a range indicator such as “12–23 of 86”; distinguish visible range from “2 matching of 7 total”. Use the actual TableState offset and row viewport.
- Compress tabs by hiding counts and shortening labels before allowing overflow. Keep the active tab visible; use a selected-tab window or compact tab selector at the smallest widths.
- Prioritise footer actions: primary action, Actions, help, back/quit. Less frequent shortcuts remain in the menu/help.
- Collapse the header's authentication/provider summary before losing the vault identity or read-only/blocked/locked state.
- Stack overview panels and allow scrolling on narrower/shorter terminals. Put blocked state, expiry and audit problems before the activity chart.
- Preserve the existing generous spacing at wide widths; do not add borders around every cell.

Suggested profiles are starting points to validate, not final hard-coded promises:

| Available terminal width | Secrets table direction | Overview direction |
| --- | --- | --- |
| 120+ | Existing broad table, with bounded secondary columns and overflow cues | Multiple panels if height is sufficient |
| 80–119 | Name, status, storage and expiry; complete metadata through details | Fewer columns or stacked sections |
| 60–79 | Name, status and one priority field; compact navigation | One scrollable column |
| Below 60 | Minimal name/status or a clear small-window message, with help/quit/cancel reachable | Minimal summary with safe navigation |

**Unicode:** [projects.rs][projects] uses character counts for displayed paths, [lists.rs][lists] for actor width, and [init/view.rs][init-view] for padding. Use existing Ratatui Line/Span display widths on **sanitised** text. Let widgets perform clipping rather than importing ratagrid's Unicode engine. Secret and vault names are ASCII validated; paths, actors and other metadata are the relevant wide/combining-character cases.

**Files:** [view/mod.rs][view] — header_bar(), tab_bar(), draw_footer(), ruled_table(); [view/secrets.rs][secrets]; [view/lists.rs][lists]; [view/projects.rs][projects]; [view/overview.rs][overview]; [app.rs][app] — overview viewport/page state; [init/view.rs][init-view]. A private **ui/view/layout.rs** can contain the small profile/column definitions.

**Tests / acceptance:** At 60/80/100/120/160 columns, selected name/status, active tab and a route to help/actions remain visible. At 80×24, all overview information remains reachable. Test resize, large counts, long names, Unicode paths/actors, combining sequences and empty lists. Counts/ranges match the filtered data. Render/resize/scroll make zero source calls.

### U07 — Fix contrast and strengthen focus without changing the identity

**Priority:** Core polish. **Effort:** Small.

**Evidence:** In the dark secrets/edit snapshots, muted selected text loses definition. [Theme::cell()][theme] neutralises styles for reverse-video selection only; paper palettes retain the original foreground colours on a blue selection background.

Calculated from the current explicit RGB constants, before terminal/font effects:

| Foreground / background combination | Approximate contrast |
| --- | --- |
| Dark muted text #8f8879 / selection #2f4a73 | 2.54:1 |
| Dark unavailable status #c06b62 / selection #2f4a73 | 2.35:1 |
| Light enabled status #5c7a55 / selection #d6e1f0 | 3.64:1 |
| Light caution #9b8d75 / screen #f5f2ec | 2.91:1 |

Use **4.5:1 as an engineering readability target for meaningful text on the controlled paper palettes**, based on [W3C's contrast guidance](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html). This is not a claim that a terminal application has achieved WCAG conformance. User-controlled terminal colours need practical checks rather than a universal numeric guarantee.

**Change:**

- Add explicit selected-text behaviour: use a readable selected foreground, or selected variants of status colours.
- Keep the text “expired”, “disabled”, “blocked”, etc.; colour must not carry the meaning alone.
- Make focused fields visibly distinct from selected table rows and disabled actions.
- Add only the semantic roles actually needed: for example selected_text, focused_control, search_match and disabled_action.
- Retain the typed Theme/Paper design, explicit Theme references, terminal-native option, no-colour behaviour and indexed-colour conversion.
- Extend theme contract tests to all roles, including callouts and combinations on selection/panel backgrounds.
- Keep the visual relationship to [paper.css][paper-css], but allow a terminal-specific semantic colour where it improves reading.

**Files:** [theme.rs][theme], selected cell rendering in [secrets.rs][secrets], [lists.rs][lists] and [projects.rs][projects], [dialogs][dialogs], [view/tests.rs][view-tests], [snapshot.rs][snapshots].

**Tests / acceptance:** Check actual resulting foreground/background pairs in dark/light paper modes and their 256-colour mapping, not just exact palette constants. Visually inspect selected enabled/disabled/expired rows, focused fields, search matches and errors in all six snapshot looks. No-colour output remains understandable.

### U08 — Add a flat contextual Actions menu

**Priority:** Core polish; high adoption value. **Effort:** Medium. **Inspiration:** tui-menu.

The current keyboard UI is capable but asks a new user to remember scattered shortcuts. A small menu makes available actions visible without replacing expert shortcuts.

**Change:**

- Offer **F2 Actions** in normal browsing, subject to manual key-availability checks on supported terminals. F2 is currently unused by the browser mapping.
- Use a small MenuState and bounded Ratatui List: label, existing shortcut, availability/reason and an existing typed action.
- Organise the flat list by relevance: inspect, edit, lifecycle actions, refresh, vault settings and help. Add separators only where useful.
- Factor a **pure** availability query out of checks such as App::can_change(), which currently also writes a message. Reuse it for menu entries, footer hints and empty-state guidance.
- Revalidate at execution. The menu is discovery, not an authorization boundary.
- Choosing Edit/Delete/Recover routes into the existing form/confirmation flow. Highlighting or scrolling never invokes an action.
- Show a concise reason for unavailable actions, such as read-only mode, no selection or an unsupported provider capability.
- Correct current inconsistencies: Overview accepts search mode without displaying search results; the empty secrets guidance advertises adding even when read-only.

A sufficient conceptual shape is:

~~~rust
// Design sketch only; these are not existing types or a compile-ready patch.
struct ActionItem {
    label: &'static str,
    shortcut: &'static str,
    action: Action,
    unavailable_reason: Option<String>,
}

struct MenuState {
    items: Vec<ActionItem>,
    selected: Option<usize>,
    scroll: usize,
}
~~~

**Files:** [app.rs][app] — Action/Mode/MenuState; [keys.rs][keys]; [edit.rs][edit] — capability seams; [view/mod.rs][view] — hints; [secrets.rs][secrets] — empty states; proposed private **ui/menu.rs** and **ui/view/menu.rs**; [theme.rs][theme].

**Tests / acceptance:** Every advertised shortcut performs the same action as its menu item. Read-only, blocked, empty-selection and capability-limited states are accurate. Disabled items cannot execute. Esc returns to the same list selection/filter. Empty/disabled-only menus and long reasons work at 60×18. Menu navigation makes no source calls.

### U09 — Expose powerful search through visible filters and safe highlighting

**Priority:** Core polish. **Effort:** Medium. **Inspiration:** Chamber.

**Change:**

- Add a small “Filter…” action with choices based on the existing supported grammar: Enabled, Disabled, Expired, Due within 30 days, and tags. Explain that the existing expiry qualifier includes already-expired entries; do not silently change it to future-only. Offer relevant audit qualifiers on the audit tab.
- Represent active filters visibly in the existing title/search area. Include “Clear filters”.
- Reuse the same query representation/evaluator as typed search. Do not maintain a second approximate filter engine.
- Define combination semantics clearly. Unqualified words remain AND terms; existing same-kind status qualifiers are OR alternatives. A single-choice status facet may replace the prior status facet for predictability, but must not silently change the existing typed-query semantics. If multiple status chips are allowed, their meaning must match that OR behaviour.
- Derive any facet counts from cached metadata and label what they count.
- Highlight matching visible metadata without damaging the selected-row foreground.
- Do not highlight with byte offsets obtained from a differently cased string. Preserve original, sanitised display text and valid UTF-8 boundaries. Qualifier matches may be indicated by a field label rather than a fabricated substring highlight.
- Keep the raw text search for advanced users. Do not add value search or background retrieval.

**Files:** [search.rs][search], [app.rs][app], [keys.rs][keys], menu additions from U08, [view/mod.rs][view], [secrets.rs][secrets], [lists.rs][lists], [projects.rs][projects], [theme.rs][theme].

**Tests / acceptance:** A chosen facet and its typed equivalent return the same rows. Combined/empty filters, clear, expiry boundaries and no-results states behave predictably. Unicode/case-conversion and sanitisation tests ensure highlighted spans reconstruct exactly the displayed metadata. Source call counts are unchanged.

### U10 — Typed sorting with stable selection

**Priority:** Core polish after U01. **Effort:** Small–medium. **Inspiration:** ratagrid.

**Change:** Add a Sort action and a compact sort indicator. Start with name, updated time and expiry on Secrets, and timestamp on Audit. Use typed values, deterministic tie-breakers and an explicit placement for missing dates. Cycle or choose ascending, descending and default order.

Keep sorted/filtered row order separate from the source metadata. A small vector of indices or a view function over cached records is enough; introduce persistent index caching only if measurement justifies it. Do not sort formatted date strings, short IDs or rendered cells.

**Files:** [app.rs][app] — per-tab sort state and shown_*(); [search.rs][search] only where view composition requires it; [secrets.rs][secrets], [lists.rs][lists], [view/mod.rs][view], menu/key wiring.

**Tests / acceptance:** Equal dates have stable ordering; missing expiry is consistent; adding a newer record does not change the selected object's identity. Sorting and filtering compose, and resetting returns to documented default order. Zero vault/provider reads.

### U11 — Make long metadata and errors fully inspectable

**Priority:** Core polish. **Effort:** Small–medium. **Inspiration:** Taskui and ratagrid.

The existing secret details should remain the main inspection flow. Add a bounded metadata inspector only where current details still truncate useful content: a long path, tags, audit detail or error message.

**Change:**

- Use an explicit “Inspect metadata” or “Details” action; preserve the current list/filter/selection underneath.
- Display wrapped, scrollable, sanitised text from the current cached record/message.
- Prefer a simple overlay initially. A split preview on wide screens is optional and must justify its extra focus state.
- Moving selection in a list must not start loading versions/activity/provider metadata. If the complete field is not cached, keep the existing explicit audited open-details action.
- Give errors a short actionable headline and a route to the complete existing safe message. Do not attach raw provider response bodies.
- A clipped field should have a visible cue; a blank cell must continue to mean genuinely absent data.

**Files:** [view/mod.rs][view] — callout()/message route; [app.rs][app]; [keys.rs][keys]; [secrets.rs][secrets], [lists.rs][lists], [projects.rs][projects]; proposed private **ui/view/inspector.rs** if needed.

**Tests / acceptance:** Long tags, long actor names, paths and audit/error details can all be read at 80×24 without modifying data. Esc restores the exact underlying state. Hostile control characters remain sanitised. Opening the cached inspector and scrolling perform no source calls.

### U12 — Improve ordinary text editing

**Priority:** Core polish, after viewport work. **Effort:** Medium.

**Evidence:** [Form::input()/erase()][edit], around lines 447–478, append and pop at the end. Dialog key handling lacks Left/Right/Home/End/Delete editing. Correcting the start of a long tag or content-type field is unnecessarily laborious.

**Change:**

- Add cursor position and horizontal viewport state for **non-secret** editable text.
- Support Left/Right, Home/End, Delete and Backspace; keep Tab/Shift-Tab for fields.
- Keep shortcuts mode-specific: an arrow in a text field must not switch tabs.
- Use valid UTF-8 boundaries and terminal-cell positions for drawing. Specify and test combining-character behaviour rather than treating byte index as screen column.
- Share small non-secret text-field presentation/input helpers where useful; do not replace secret/password/credential buffers with ordinary cloned strings.
- Handle paste as one input event only if explicitly supported, with existing length/character rules and no automatic submission from embedded newlines. Treat broader secret-field editing/paste as a separate reviewed change.

**Files:** [edit.rs][edit], [keys.rs][keys], [view/dialog.rs][dialogs], [app.rs][app]; [setup/wizard.rs][setup-wizard] and [init/wizard.rs][init-wizard] only for clearly non-secret fields; their views and tests. Proposed private **ui/text_input.rs**.

**Tests / acceptance:** Edit the first and middle characters of a long existing tag/path without deleting the suffix. Validate UTF-8 and cursor visibility after resize. Metadata input cannot trigger commands; existing secret buffers, hidden prompts and redaction remain intact.

### U13 — Show freshness and honest operation feedback

**Priority:** Core polish for messages; optional architecture change for background work. **Effort:** Small for freshness, large for asynchronous work.

**Evidence:** Refresh/inspection/provider work currently runs synchronously before the next draw in [ui/mod.rs][ui-mod] and [app.rs][app]. A slow operation can look like a frozen UI. The existing failed-refresh message correctly says the old data is still shown, but long messages are limited to one line.

**Change in the first increment:**

- Record the last successful explicit load/refresh time and show “Snapshot from HH:MM” or “Showing previous data — refresh failed”.
- Distinguish success, warning and failure textually.
- Draw an honest “Refreshing metadata…”/“Opening details…” state before starting a synchronous operation, where the existing control flow permits it.
- Do not show a fake progress percentage, animation that cannot tick, working Cancel button, or responsive lock promise while the operation is blocking.
- Keep errors persistent until acknowledged or superseded appropriately; do not hide a failed operation behind a transient success toast.
- Measure representative refresh/provider durations before deciding that an asynchronous redesign is necessary.

If asynchronous loading is later needed, make it its own design and test batch: explicit request/session generation, stale-result rejection after vault change/lock, key ownership and cancellation semantics, and exactly-once audited calls. Drawing a spinner alone does not solve blocking work. Do not introduce automatic refresh or mutation retries.

**Files:** [app.rs][app] — Message/freshness/operation state; [ui/mod.rs][ui-mod] — request execution/draw order; [session.rs][session] — successful load timestamps as appropriate; [view/mod.rs][view], [view/overview.rs][overview].

**Tests / acceptance:** Failed refresh does not mark old data fresh. One explicit refresh makes only the documented calls. Slow/failing fakes produce accurate status. Lock/vault-change handling is tested before any background worker is introduced.

### U14 — Optional theme preview and idle-lock warning

**Priority:** Optional; follow core polish. **Effort:** Medium each. **Inspiration:** Opaline and Chamber.

**Theme preview:** Offer Dark / Light / Terminal in the Actions menu. Preview locally, Enter applies, Esc restores the exact prior choice. Keep this session-local initially; no theme-file loader, global state or new dependency. Respect NO_COLOR throughout. [Opaline's selector](https://github.com/hyperb1iss/opaline/blob/c9edc3df25396f0688e789c73e8ec3019fd52b5e/src/widgets/theme_selector.rs#L158) and [cancel test](https://github.com/hyperb1iss/opaline/blob/c9edc3df25396f0688e789c73e8ec3019fd52b5e/tests/theme_selector_tests.rs#L41) are behaviour references.

**Idle warning:** Near the existing timeout, show a textual “Locks in 30s”. Derive it from the existing inactivity clock. A bounded display tick must not reset inactivity, trigger metadata reads or prolong the key lifetime. Keep the screen quiet before the warning window.

**Files:** [theme.rs][theme], [ui/mod.rs][ui-mod], [app.rs][app], [keys.rs][keys], [view/mod.rs][view], menu state.

**Tests / acceptance:** Preview then cancel, Enter without moving, quit, resize, NO_COLOR and idle-lock during preview. Fake-clock tests establish that warning ticks do not defer locking. Lock closes transient UI state and drops session metadata/key ownership as before. Test the two additions separately.

### U15 — Optional path picker, only for a demonstrated workflow

**Priority:** Later. **Effort:** Medium. **Inspiration:** ratatui-explorer.

Start with improved text entry. Add a picker only if usability testing shows that entering a project folder or import path is a significant obstacle.

Implement a small explicit directory browser returning a native PathBuf to the existing validated workflow. Retain optional selection and scroll state, list the parent/directories/files deliberately, and update the displayed directory only after listing succeeds. Keep native path identity separate from sanitised display text: for non-UTF-8 names, preserve the PathBuf or return a clear unsupported-path error; never reconstruct the accepted path from a lossy label. Bound displayed results. A synchronous directory read on a slow location cannot promise responsive cancellation; that requires separate worker/lifecycle design. Do not read file contents or recursively search for secrets.

**Files:** The actual consuming wizard ([init/wizard.rs][init-wizard] / [init/view.rs][init-view] for a project workflow); proposed private **ui/path_picker.rs** and **ui/view/path_picker.rs**. Do not add it to unrelated browser screens.

**Tests / acceptance:** Empty/root directories, denied access, disappearing entries, symlinks, long paths, Windows hidden attributes, non-UTF-8 names on supported platforms and cancel. Failure preserves the previous directory/selection. The existing consumer still performs its own path validation.

## Illustrative compact presentation

This is a text sketch of the proposed behaviour, not a screenshot or implemented design. It combines responsive columns, visible filters, range reporting and an Actions entry. The complete metadata stays available through the existing explicit detail flow.

~~~text
 SourceOrrery · development                              metadata only
 1 Overview  [2 Secrets]  3 Projects  4 Deleted  5 Audit  6 Vaults

 SECRETS  4 matching of 7       status:enabled       Sort: Name ↑
 ─────────────────────────────────────────────────────────────────────
 NAME                     STATUS    STORAGE       EXPIRES UTC
 ─────────────────────────────────────────────────────────────────────
 > database-password      enabled   Local         —
   github-webhook-secret  enabled   Local         —
   payments-api-token     enabled   HashiCorp      —
   stripe-api-key         enabled   Local         2026-11-09 06:55
 ─────────────────────────────────────────────────────────────────────
 1–4 of 4                        Enter details includes tags and versions

 ↑↓ move   Enter details   F2 Actions   / search   ? help   q quit
~~~

The contextual menu should use plain labels and preserve existing confirmations:

~~~text
 Actions · database-password
 ───────────────────────────────────────────────
 > Open details                           Enter
   Edit metadata                              e
   New version                                n
   Delete secret                              d
 ───────────────────────────────────────────────
   Search text                                /
   Filter…
   Sort…
   Refresh metadata                           r
 ───────────────────────────────────────────────
 Enter choose                         Esc cancel
~~~

In read-only mode, mutation entries should show a short unavailable reason and refuse execution. Menu labels, ordering and density should be tested with first-time users before treating this sketch as the final design.

## Small implementation batches

Estimates are rough engineering effort for someone familiar with this code, including focused tests. They are not elapsed-time promises. Complete B01–B08 first, then reassess remaining value with users. Each batch should have its own reviewable diff and avoid mixing storage remediation with UI work.

| Batch | Scope / dependency | Affected files | Tests and acceptance gate | Indicative effort |
| --- | --- | --- | --- | --- |
| **B01** | U01: identity-preserving refresh. Recheck completed remediation first. | app.rs, edit.rs; session.rs if needed | Insert/remove/reorder fixtures; same target survives or becomes unselected; no accidental neighbour mutation | 1–2 days |
| **B02** | U02: one-shot review/commit inputs. Independent of B01. | keys.rs, app.rs, setup/mod.rs, init/mod.rs | Press/repeat/release regression and one-write assertion; manual terminal check | 0.5–1 day |
| **B03** | U03 + U04: help and project scroll state. | app.rs, keys.rs, view/mod.rs, view/projects.rs | All help sections and 50 declarations reachable at 80×24; zero reads while scrolling | 1–2 days |
| **B04** | U05: bounded forms/reviews and accurate focus visibility. After B02. | edit.rs, view/dialog.rs, setup/init view and wizard modules; optional viewport helper | Long fields/errors, last-field focus, resize and QR fallback; controls reachable | 2–3 days |
| **B05** | U06 tables/widths/ranges first. After B01; reuse B03 scroll state. | view/mod.rs, secrets.rs, lists.rs, projects.rs, init/view.rs | Width matrix, Unicode metadata and filtered-range correctness | 1–2 days |
| **B06** | U06 chrome/overview separately. After B05. | view/mod.rs, overview.rs, app.rs, setup/init rails as needed | Active tab/help/state visible; all overview sections reachable at 80×24 | 1–2 days |
| **B07** | U07 palette/focus readability. Can run after B04 in parallel with layout work if files are coordinated. | theme.rs, cell/focus renderers, view/tests.rs, snapshot.rs | Semantic colour-pair checks and six-look visual inspection | 0.5–1.5 days |
| **B08** | U08 action availability/menu. After B01–B04 and B07. | app.rs, keys.rs, edit.rs, view/mod.rs, secrets.rs; new menu modules | Menu/key equivalence; read-only/blocked/provider/empty states; no writes from navigation | 2–3 days |
| **B09** | U09 visible filters/highlights. After B01, B05, B07, B08. | search.rs, app.rs, menu/view modules, theme.rs | Facet/text equivalence, sanitised highlighting, empty/combined filters, no source reads | 2–3 days |
| **B10** | U10 typed sorting. After B01, B05, B08. | app.rs, keys/menu, secrets.rs, lists.rs, view/mod.rs | Typed date/missing-value/tie-break cases; selection identity preserved | 1–2 days |
| **B11** | U11 cached inspector and complete error details. After B04, B05, B08. | app.rs, keys/menu, view/mod.rs; optional inspector module | Long metadata readable; exact return state; no additional source reads | 1–2 days |
| **B12** | U12 non-secret text editing. After B02, B04. | edit.rs, keys.rs, dialogs; limited wizard fields; new text_input helper | Mid-string edits, UTF-8/cursor/resize; secret-buffer regression checks | 2–3 days |
| **B13** | U13 freshness and synchronous feedback only. After B08/B11. | app.rs, ui/mod.rs, session.rs, view/mod.rs, overview.rs | Old-data/failure/slow-operation tests; explicit call counts unchanged | 1–2 days |
| **B14** | U14 theme preview. Optional, after B07/B08. | theme.rs, app.rs, ui/mod.rs, keys/menu/view | Exact cancel restoration, immediate Enter, NO_COLOR, lock during preview | 1–2 days |
| **B15** | U14 idle warning. Optional, after B13. | ui/mod.rs, app.rs, view/mod.rs | Deterministic clock tests; ticks neither reset idle nor read metadata | 1–2 days |
| **B16** | U15 picker. Optional, after user validation and B12. | Consuming wizard, new picker modules | Filesystem error/empty/path/cancel cases; no content previews | 2–4 days |

**Separate later decision:** Asynchronous/paged loading from U13. Do not fold it into B13 or promise a duration before measuring operations and reviewing session/key ownership. It is substantially more complex than the visual improvements.

Every batch adds its relevant fixtures to [view/tests.rs][view-tests], the inline state/key tests or wizard tests, plus selected [snapshot.rs][snapshots] screens. Do not wait until the end to test the combined behaviour.

## Validation and usability acceptance

### Automated checks

Use existing Ratatui TestBackend, fake sources/editors and wizard fakes. No snapshot-testing or UI toolkit crate is needed.

- **Baseline sizes:** 80×24 is the primary complete workflow target; 60×18 tests compact behaviour; 120×40 covers wide layouts. Add 100-column and 160-column table tests where column transitions matter. Exercise very small/zero-sized render areas for safe rendering and an exit path.
- **Long data:** Many rows, a 50-secret project, long tags/paths/provider names/errors, CJK and combining-character metadata, empty results and large counts.
- **State transitions:** Resize during help/form/menu/inspection, filter then sort then refresh, disappear/reappear targets, return from detail and lock while transient UI is open.
- **Themes:** All six existing snapshot looks for representative changes, with dedicated selected/focused/disabled/error/match combinations. Avoid multiplying every state by every size when a focused matrix covers the behaviour.
- **Boundaries:** Fake call-count assertions for navigation, redraw, resize, sorting, filtering, help, menus and cached inspection. Keep existing **each_thing_is_read_once_and_never_a_value**, edit, read-only, blocked and lock regressions.
- **Provider work:** No automatic retry or duplicate audited call introduced by a redraw/status transition.
- **Redaction:** Use synthetic fixtures only. Browser fixtures remain value-free; setup recovery/authenticator fixtures must stay deliberately synthetic.

Suggested commands **for the implementation stage; not run by this review**:

~~~powershell
cargo test -p sourceorrery-cli --locked ui::
cargo fmt --all -- --check
cargo clippy -p sourceorrery-cli --all-targets --locked -- -D warnings
cargo test -p sourceorrery-cli --locked ui::snapshot::write_design_snapshots -- --ignored
~~~

Run the repository's required broader checks from [building.md][building] before merging a completed UI change. Snapshot generation is an explicit operation and writes fixture output; keep it separate from ordinary test runs.

### Human checks that matter for adoption

Recruit a few first-time users, including someone who does not routinely use terminal applications. Treat this as qualitative validation, not statistical evidence of adoption.

Ask them to:

1. Open a vault and identify its name, state and storage location.
2. Find a secret that expires soon without being told the query syntax.
3. Find which projects use that secret.
4. Inspect a long path/tag and return to the same selected row.
5. Discover an allowed edit through Actions, understand the review and cancel safely.
6. Explain why an action is unavailable in read-only mode.
7. Resize to 80×24, find help, and continue without losing their place.
8. Complete the setup review and explain what will be saved.
9. Distinguish a failed refresh showing old data from a fresh successful result.

Record hesitations, incorrect choices, hidden controls and mistaken interpretations. A good acceptance outcome is that users can complete these without the developer supplying undocumented keys. Check keyboard-only use, visible focus, no-colour mode, Windows Terminal and a non-Windows terminal. Include a basic terminal screen-reader check; do not assume screenshots prove accessibility.

## Design boundaries for this work

- Preserve the [MetadataSource][source] value-free interface and separate editor. Menu, filter, preview and theme work should not widen them.
- Keep audited reads explicit. No hover/selection-triggered provider calls or automatic refresh.
- Keep mutations inside the established forms/confirmations and provider capability checks.
- Preserve sanitisation before rendering external names, paths, messages and search text.
- Keep native secret-value prompts on their current flow. Preserve existing typed secret-state ownership and clearing behaviour in setup; avoid introducing persistent copies of sensitive text.
- Avoid persistent UI state that stores queries, metadata or paths merely for convenience. Session-local preferences are enough for this increment.
- Keep labels and text cues usable without icons, special fonts, mouse support or colour.
- Do not add a general widget framework, theme language, nested command system or file manager to achieve these improvements.

The recommended investment is in reliable interaction and legibility first. SourceOrrery already has a visual identity; making it consistently understandable at ordinary terminal sizes will do more for polish than importing another application's layout.

## Local source map

References below are relative to this document for portability. In the batch table, unqualified Rust filenames refer to the corresponding UI module linked here.

[app]: ../crates/sourceorrery-cli/src/ui/app.rs
[keys]: ../crates/sourceorrery-cli/src/ui/keys.rs
[edit]: ../crates/sourceorrery-cli/src/ui/edit.rs
[session]: ../crates/sourceorrery-cli/src/ui/session.rs
[source]: ../crates/sourceorrery-cli/src/ui/source.rs
[search]: ../crates/sourceorrery-cli/src/ui/search.rs
[theme]: ../crates/sourceorrery-cli/src/ui/theme.rs
[ui-mod]: ../crates/sourceorrery-cli/src/ui/mod.rs
[view]: ../crates/sourceorrery-cli/src/ui/view/mod.rs
[secrets]: ../crates/sourceorrery-cli/src/ui/view/secrets.rs
[lists]: ../crates/sourceorrery-cli/src/ui/view/lists.rs
[projects]: ../crates/sourceorrery-cli/src/ui/view/projects.rs
[overview]: ../crates/sourceorrery-cli/src/ui/view/overview.rs
[dialogs]: ../crates/sourceorrery-cli/src/ui/view/dialog.rs
[view-tests]: ../crates/sourceorrery-cli/src/ui/view/tests.rs
[snapshots]: ../crates/sourceorrery-cli/src/ui/snapshot.rs
[setup-mod]: ../crates/sourceorrery-cli/src/ui/setup/mod.rs
[setup-view]: ../crates/sourceorrery-cli/src/ui/setup/view.rs
[setup-wizard]: ../crates/sourceorrery-cli/src/ui/setup/wizard.rs
[init-mod]: ../crates/sourceorrery-cli/src/ui/init/mod.rs
[init-view]: ../crates/sourceorrery-cli/src/ui/init/view.rs
[init-wizard]: ../crates/sourceorrery-cli/src/ui/init/wizard.rs
[paper-css]: ../site/src/styles/paper.css
[building]: building.md

