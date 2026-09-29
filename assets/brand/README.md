# conduit — logo (1b "Inspection chamber")

A nano product. Built on the nano glyph grid: strokes are one cell wide, ends are fully rounded (r = ½ cell), and diagonal steps are joined with concave fillets (r = ½ cell).

## Files
- `svg/` — master vectors. Use these wherever possible.
  - `conduit-lockup-*` — mark + wordmark (primary)
  - `conduit-lockup-single-accent-on-dark` — i-dot in white, only the mark's dot is pink
  - `conduit-mark-*` — standalone mark
  - `conduit-wordmark-*` — wordmark alone
  - `conduit-app-icon.svg`, `favicon.svg`
- `png/` — rasters: lockup/mark at 80px per cell (transparent), app icon at 1024/512/180/64/32

## Color
| Role | Hex |
|---|---|
| Glyphs on dark | `#FFFFFF` |
| Glyphs on light | `#0D0D12` |
| Packet dot (accent) | `#ED2377` (nano pink) |
| Icon tile | `#0D0D12` |

The dot is the only accent. Never recolor the glyphs. Use the mono versions when only one color is possible.

## Geometry (grid units, 1 unit = 1 cell)
- Mark: 9 × 5. The o is 5 × 5 at cols 2–6; the pipe runs through row 2; the dot sits at the center (4, 2), r = 0.5.
- Wordmark: x-height is 5, ascenders are +2 (total 7). Letter gap is 0.6.
- Lockup: mark aligned to the x-height (rows 2–6); 2.4 units between mark and wordmark.
- Clearspace: ≥ 2 units on every side.
- Minimum size: lockup 14px tall, mark 16px wide.

## Don't
- Stretch, rotate, outline, or add effects/gradients
- Swap in a font. The letters are custom geometry, not type
- Move the dot out of the chamber
