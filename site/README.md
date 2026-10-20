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

## Deployment

Not configured yet. `.github/workflows/docs.yml` builds the site on every
push to `main` and every pull request and keeps `dist/` as an artifact; the
TODO in that file lists the Cloudflare Pages and GitHub Pages options.
