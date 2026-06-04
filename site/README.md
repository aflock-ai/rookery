# cilock-docs

Docusaurus site for cilock product documentation. Deployed to `https://cilock.dev` via Cloudflare Pages.

## Local development

```bash
npm install
npm run start
```

Dev server runs at `http://localhost:3000/`.

## Build

```bash
npm run build
npm run serve
```

Static output is written to `build/` and is what gets uploaded to Cloudflare Pages (or any static host).

## Project layout

```
docs/
  intro.md
  getting-started/   # install, first attestation, first verification, quickstart
  concepts/          # the "why" docs (what cilock is doing under the hood)
  tutorials/         # end-to-end paths (GH Actions, GitLab, container, audit, etc.)
  guides/            # task-oriented "how do I..." pages
  reference/         # CLI flags, action.yml inputs, attestor catalog, schemas
  ecosystem/         # how cilock relates to aflock, rookery, archivista, witness, and the TestifySec platform
  faq.md
src/css/custom.css   # theme tokens
docusaurus.config.js # site config
sidebars.js          # auto-generated per directory
```

Every page under `docs/` is currently a stub with frontmatter and a one-line scope note. Replace stub bodies as content is written.

## Deploying to cilock.dev

The site is built with `baseUrl: '/'` and deployed to a Cloudflare Pages project named `cilock` with `cilock.dev` set as the custom domain. Pushes to `main` trigger `.github/workflows/deploy-cloudflare.yml`, which builds `build/` and runs `wrangler pages deploy`.

Required repo secrets:

- `CLOUDFLARE_API_TOKEN` — scoped to `Pages:Edit` on the `cilock` project.
- `CLOUDFLARE_ACCOUNT_ID` — the TestifySec / aflock Cloudflare account ID.
