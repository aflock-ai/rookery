# Social / OG card templates

HTML templates for the cilock.dev Open Graph cards (the image that unfurls when a
page is shared on LinkedIn/X/Slack). Crawlers don't run JS, so the card is a static
PNG referenced by `og:image` — these templates are the source for those PNGs.

- `evergreen-card.html` → `static/img/cilock-og.png` (site-wide default, version-agnostic)
- `release-card.html`   → `static/img/og/v<version>.png` (per-release; `og:image` on the
  download page points at the versioned file — the immutable `/img/*` header then keeps
  LinkedIn from serving a stale card)

## Regenerate (per release)
Edit the version/recap/highlights in `release-card.html`, then render at 1200×630:

    chrome --headless --disable-gpu --hide-scrollbars \
      --screenshot=../../static/img/og/v<version>.png --window-size=1200,630 \
      release-card.html

Then bump `OG_IMAGE` in `src/pages/download.tsx` to the new `/img/og/v<version>.png`.
(Follow-up: a build-time `satori` step can do this automatically from release frontmatter.)
