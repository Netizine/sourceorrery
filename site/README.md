# sourceorrery.ai

The public documentation site for SourceOrrery, built with
[Astro Starlight](https://starlight.astro.build/).

`../docs/` is the source of truth. Nothing under `src/content/docs/` that is
listed in `src/content/docs/.gitignore` is edited by hand: `scripts/sync-docs.mjs`
regenerates those pages before every `dev` and `build` from

- `docs/*.md` and `docs/adr/*.md` (title from the H1, links rewritten), and
- `crates/sourceorrery-core/src/error.rs` (the error-code table).

Hand-written pages: `src/content/docs/index.mdx` (landing),
`getting-started.mdx` and `guides/headless.md`.

## Commands

```bash
npm ci              # Node 22.12+
npm run dev         # sync docs, then serve at http://localhost:4321
npm run build       # sync docs, build to dist/, then check every internal link
npm run sync        # regenerate the synced pages only
npm run logo-mark   # regenerate src/assets/logo-mark.png and public/favicon.png from logo.png
```

The site header uses `logo-mark.png`, the orrery emblem cropped from
`logo.png`, because the full logo's dark wordmark is invisible on the dark
theme; the name is rendered as text beside it.

## Dependency overrides

`package.json` pins `postcss-selector-parser` to `^7.1.6` through `overrides`
(advisory GHSA-rj75-hqrm-r3gf). It is reached only via Starlight's
expressive-code → postcss-nested 6, which still declares the vulnerable 6.x
line; the 7.x API is unchanged for that use. Drop the override once
`@expressive-code/core` depends on postcss-nested 7 or later.

## Theme

`src/styles/paper.css` holds the whole look: warm paper palette (light and
dark), Source Serif 4 for text, Inter for interface labels, JetBrains Mono for
code, booktabs-style tables and left-bar callouts. The landing page uses the
cover-style hero in `src/components/Hero.astro`. Fonts are self-hosted from
the `@fontsource-variable/*` packages.

Build with the dev server stopped: `astro dev` and `astro build` share the
Expressive Code cache, and building while `npm run dev` is running can leave
pages pointing at stylesheet hashes that the build did not emit (the link
check then fails).

## Deployment

Azure Static Web Apps, through the Azure-generated workflow
`.github/workflows/azure-static-web-apps-*.yml` (app location `/site`, no API,
output `dist`). Every push to `main` builds and publishes the site; pull
requests get preview environments. `.github/workflows/docs.yml` remains as the
build-and-link-check gate. The custom domain `sourceorrery.ai` is configured in
the Azure portal under the static web app's *Custom domains*.
