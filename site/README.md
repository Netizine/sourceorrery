# sourceorrery.ai

Documentation for the **SourceOrrery 0.2.0** build, using Astro 7 and Starlight.
The public site is deployed separately; local changes do not publish it.

## Work on the documentation

Use Node **22.19+** (or Node 24 LTS). Set `FONTAWESOME_NPM_AUTH_TOKEN` in your
process environment using your secret manager before installing dependencies.
The checked-in `.npmrc` contains registry scopes and an environment-variable
placeholder only. Never replace it with a real token or commit credentials.

```bash
npm ci
npm test
npm run build
npm run dev -- --background
```

`npm run build` syncs documentation, produces the static site, indexes search,
and checks every internal page, asset and fragment link. The focused tests
cover Git metadata, reading estimates, callouts and external links in Markdown
and MDX. Manage the background dev server with `npx astro dev status`,
`npx astro dev logs` and `npx astro dev stop`.

Stop the dev server before building: dev and build share Expressive Code's
cache. Use `npm run preview` after a build to verify production search; search
is not indexed in the development server. After changing code-theme settings,
use `npm run build -- --force` to rebuild cached content and its stylesheet links.

## Content sources

`../docs/` is the source of truth for reference pages, guides, SDKs and ADRs.
`scripts/sync-docs.mjs` regenerates their counterparts in `src/content/docs/`
and the error-code table from `crates/sourceorrery-core/src/error.rs` before
every dev/build. Files listed in the content directory's `.gitignore` are
generated: edit the original source instead.

The homepage (`index.mdx`), `getting-started.mdx` and `guides/headless.md` are
hand-written in `src/content/docs/`. Keep instructions and release links on
0.2.0. The authenticated broker and agent isolation remain future work.

Platform headings between `<!-- tabs: os -->` and `<!-- /tabs -->` in source
Markdown become Starlight tabs. `syncKey="os"` remembers the selected platform
across pages. They remain ordinary readable headings on GitHub.

A line `<!-- walkthrough: setup -->` (or `browser`, `init`) in source Markdown
becomes `src/components/Walkthrough.astro`: the CLI's own screens one at a
time, in a dark or a light terminal following the site's theme, with a
caption per screen. Authored MDX imports the component directly. The slides
and captions are `src/lib/walkthroughs.mjs`; the screens are the CLI's design
snapshots, copied into `public/walkthrough/` by `npm run walkthroughs`. After
a change to the screens:

```bash
cargo test -p sourceorrery-cli ui::snapshot -- --ignored   # from the repository root
npm run walkthroughs
```

The snapshots are drawn as a made-up person, `alex`, and the copy refuses a
screen that shows this machine's user or host, a temporary folder or any
other home directory: what it writes is published.

Mark important information with GitHub alerts, which render as accessible,
themed callouts on the website:

```markdown
> [!NOTE]
> Useful context for the next step.

> [!WARNING]
> A consequence the reader needs to understand before continuing.
```

`NOTE`, `TIP`, `IMPORTANT`, `WARNING` and `CAUTION` are supported. Native
`:::note`, `:::tip`, `:::caution` and `:::danger` work too. In authored MDX,
import `src/components/Aside.astro` for the same appearance and local icons.

## Page metadata and links

`src/lib/docs-loader.mjs` wraps Starlight's content loader. Each generated
page records `sourceFile`, so its update date comes from **the original
source file's Git history**, not the generated copy or the build clock.
Authored pages use their own history. Cached content is refreshed after new
commits. When history is unavailable, the date is omitted. CI checkouts use
`fetch-depth: 0`; source archives can still build without Git.

Reading estimates count prose and code at 200 words per minute. They are
labelled as reading estimates, not time to finish a tutorial. Page descriptions,
reading estimates and dates appear above the article.

External HTTP(S) links open in a new tab with `noopener noreferrer`, a local
SVG indicator and an accessible notice. Internal links and `mailto:` links
keep their normal behaviour. There is intentionally no "Edit page" link.

## Design and local assets

`src/styles/paper.css` preserves the original paper theme: warm cream and navy
in light mode, warm charcoal in dark mode, serif text, fine borders and square
panels. Keep this visual identity when adding documentation features. Fonts are
self-hosted through Fontsource: **Source Serif 4** for prose and headings,
**Inter** for UI, and **Google Sans Code** for code. Expressive Code provides
Shiki highlighting, filenames, terminal frames and copy buttons.

Display titles and the header use a split wordmark: bold upright `Source` and
lighter italic `Orrery`, matching the hero typography. `BrandText.astro` and
the heading plugin apply it without changing heading IDs or source text.
Leave paragraphs, code, package names and uppercase labels unstyled.

Font Awesome Kit **515c69ad68**, revision **4** (`@awesome.me/kit-515c69ad68`
1.0.4), is installed as a build dependency. That revision contains **duotone
thin**, brands and the custom `sourceorrery` mark. `src/lib/font-awesome.mjs`
resolves definitions; `FAIcon.astro` and the Markdown plugins emit SVG paths
into the built HTML. Only icons used on each page are delivered. There is no
hosted Kit script, icon font download or browser request to Font Awesome.
Use `FAIcon` with `family="duotone"`, `"brands"` or `"kit"`. Missing icons fail
the build. The two SVG layers use theme colours and contrast-aware opacity.
See `.font-awesome.md` for the integration details.

To refresh the kit after editing it, authenticate through the environment,
run `npm update @awesome.me/kit-515c69ad68`, review the new revision and run the
tests/build again. Do not commit `node_modules` or credentials.

The website uses no analytics, tracking cookies or third-party asset requests.
Theme and platform-tab preferences stay in browser storage. Keep the original
homepage privacy promise intact. External websites are visited only when the
reader follows a link.

Native cross-document view transitions provide a short fade in supporting
browsers and respect reduced-motion preferences. Standard navigation remains
the fallback; no client router replaces Starlight's search, tabs or controls.
Starlight already styles rendered Markdown, so Tailwind Typography is not an
additional dependency. The existing architecture diagram is a single local,
theme-aware SVG; dynamic image discovery would add no benefit for it.

The architecture diagram remains in `src/assets/sourceorrery-architecture.svg`.
`ArchitectureDiagram.astro` synchronises its theme. The tab favicon is local;
`npm run favicon` regenerates its PNG fallback.

Design references: [CocoIndex documentation](https://cocoindex.io/docs/getting_started/installation/),
[Astro view transitions](https://docs.astro.build/en/guides/view-transitions/),
[syntax highlighting](https://docs.astro.build/en/guides/syntax-highlighting/),
[Git modified dates](https://docs.astro.build/en/recipes/modified-time/),
[reading time](https://docs.astro.build/en/recipes/reading-time/) and
[fonts](https://docs.astro.build/en/guides/fonts/).

## Deployment

`.github/workflows/docs.yml` runs the documentation checks. The Azure Static
Web Apps workflow builds `/site` and deploys `dist/` on pushes to `main`, with
PR previews. Both installation jobs read the repository Actions secret
`FONTAWESOME_NPM_AUTH_TOKEN`; configure it before publishing these changes.
The token is needed only at dependency installation, never in the browser or
built site. Fork PRs do not receive repository secrets and cannot freshly
install this private package; use a trusted maintainer build to validate them.
Do not expose the token to untrusted PR code.

`sourceorrery.ai` is configured under the static web app's Custom domains.
The `postcss-selector-parser` override remains until Expressive Code's
transitive dependency no longer requires the vulnerable version.
