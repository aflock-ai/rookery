# cilock brand assets

Canonical logo kit for **CI/lock**. All logos are clean 2-color vectors derived
from the master artwork (`source-logo.png`).

## Palette

| Role  | Hex       | Notes                          |
|-------|-----------|--------------------------------|
| Navy  | `#0A1330` | Primary. Linework & wordmark.  |
| Cyan  | `#00B8DA` | Accent. The `/` and chevrons.  |
| White | `#FFFFFF` | Knockout on dark backgrounds.  |

## Lockups (`svg/`)

| File                | What                                              |
|---------------------|---------------------------------------------------|
| `horizontal.svg`    | Primary lockup — wordmark left, crest mark right. |
| `stacked.svg`       | Crest mark above the wordmark (square-ish).        |
| `mark.svg`          | Crest mark only (icon / app / favicon source).     |
| `wordmark.svg`      | `CI/lock` wordmark only.                            |

Each comes in three variants:

- *(default)* — full color (navy + cyan).
- `-white` — solid white knockout, for dark/navy backgrounds.
- `-mono` — solid navy, single-color (print, stamps, faxable).

## Raster exports (`png/`)

Transparent-background PNGs: `cilock-horizontal-{1200,2400}.png`,
`cilock-stacked-1200.png`, `cilock-mark-{512,1024}.png`,
`cilock-wordmark-1200.png`, plus `favicon-{32,64,180,512}.png` and `favicon.ico`.

## Usage

- Prefer **SVG** everywhere it's supported; rasterize from SVG when you need PNG.
- Keep clear space around the logo of at least the cap-height of the wordmark.
- On dark backgrounds use the `-white` variant; never place the navy logo on a
  dark fill.
- Don't recolor, rotate, stretch, or add effects. Don't separate the crest from
  the wordmark in the lockups (use `mark.svg` if you need the icon alone).
- Minimum sizes: mark ≥ 24px, horizontal lockup ≥ 120px wide.

## Regenerating

The SVGs were traced from `source-logo.png`: posterize to the two brand colors,
then vectorize (`vtracer --mode spline`), unify the navy fills, and compose the
lockups. PNGs/favicons are rendered from the SVGs (`rsvg-convert` / ImageMagick).
