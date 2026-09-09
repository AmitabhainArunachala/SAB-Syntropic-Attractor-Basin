---
name: SAB public claim inspection
description: Observed shared tokens and scoped dossier patterns.
colors:
  accent: "#114e8a"
  bg: "#f4f3ef"
  surface: "#fffdf6"
  surface-raised: "#ffffff"
  ink: "#1e1d1a"
  muted: "#6f6a5f"
  border: "#d8d1c0"
  dark-accent: "#76b8ba"
  dark-bg: "#0b111f"
  dark-surface: "#131d33"
  dark-surface-raised: "#1a2744"
  dark-ink: "#f1efea"
  dark-muted: "#c8c5bc"
  dark-border: "#30405f"
typography:
  body:
    fontFamily: "'Space Grotesk', 'Avenir Next', 'Segoe UI', sans-serif"
    lineHeight: 1.55
  dossier-headline:
    fontFamily: "'Space Grotesk', 'Avenir Next', 'Segoe UI', sans-serif"
    fontSize: "clamp(1.8rem, 3.3vw, 2.65rem)"
    fontWeight: 600
    lineHeight: 1.18
    letterSpacing: "-0.02em"
  dossier-title:
    fontFamily: "'Space Grotesk', 'Avenir Next', 'Segoe UI', sans-serif"
    fontSize: "clamp(1.25rem, 2.2vw, 1.6rem)"
    fontWeight: 600
    lineHeight: 1.3
  dossier-prose:
    fontFamily: "'Spectral', 'Palatino Linotype', 'Book Antiqua', Palatino, serif"
    fontSize: "clamp(1.15rem, 2vw, 1.4rem)"
    lineHeight: 1.65
  dossier-record:
    fontFamily: "'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "0.8125rem"
    lineHeight: 1.65
rounded:
  dossier-state: "6px"
  dossier-control: "8px"
  notice: "12px"
spacing:
  xs: "0.25rem"
  sm: "0.5rem"
  md: "1rem"
  lg: "1.5rem"
  xl: "2rem"
  2xl: "3rem"
components:
  dossier-button:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.bg}"
    rounded: "{rounded.dossier-control}"
    padding: "0.65rem 1rem"
  dossier-search:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.dossier-control}"
    padding: "0.65rem 0.8rem"
  dossier-section-nav:
    textColor: "{colors.accent}"
    padding: "1rem 0"
  dossier-decision:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.ink}"
    rounded: "{rounded.notice}"
    padding: "1rem 1.25rem"
  dossier-check:
    textColor: "{colors.ink}"
    padding: "0.35rem 0"
  dossier-json:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.ink}"
    typography: "{typography.dossier-record}"
    rounded: "{rounded.dossier-control}"
    padding: "1rem"
---

# Design System: SAB public claim inspection

## Overview

This reference records the public claim dossier, claim ledger, and shared SAB shell as implemented. The shared palette and declared font stacks come from `agora/tailwind.css` and its compiled `agora/static/web.css`; the local reading patterns come from `agora/static/dossier.css` and `agora/static/reliance.css`. Tokens prefixed `dossier-` apply to claim inspection, not to every route.

The views use a text-led document layout: headings, prose, labeled facts, ruled records, and native disclosures. Cream surfaces and a blue accent form the light theme; navy surfaces and a teal accent form the dark theme. The feature contract remains in [Public claim inspection](docs/PUBLIC_CLAIM_DOSSIER.md).

**Key Characteristics:**

- Shared theme variables for surfaces, text, borders, and focus.
- Sans-serif interface text, serif claim prose, and monospace records.
- Written states, wrapping records, and native disclosure controls.

## Colors

### Primary

`accent` supplies links, primary actions, text selection, and focus outlines. Its dark counterpart is teal. Component tokens above show the light theme; live components use the shared CSS variables, whose `.dark` overrides are recorded as `dark-*` tokens.

### Neutral

`bg` is the page canvas; `surface` is the field surface; `surface-raised` separates notices and JSON blocks. `ink` carries primary text, `muted` carries labels and secondary text, and `border` supplies the dossier's thin rules. The dark theme preserves these roles.

**The Theme Inheritance Rule.** Dossier surfaces, text, borders, links, and focus outlines resolve through the shared color variables in both themes.

## Typography

The shell declares Space Grotesk for headings and interface text, Spectral for prose, and IBM Plex Mono for record content, with the fallback stacks captured above. These are source declarations, not a new display-face choice.

Within the dossier, the responsive headline leads the hierarchy, section titles step down, and record headings use a compact size (1.05rem). Exact claim prose uses the serif role; quoted challenge fragments use the same family. Paragraphs use a relaxed line height (1.65) and a reading width (72ch). Inline identifiers use monospace (0.84em); expanded records use `dossier-record`. Secondary labels and notes range from 0.8rem to 0.9375rem. The observed ramp is role-based rather than a uniform modular scale.

## Layout

The shared shell is centered with a maximum width (1100px), side padding (1rem), and wider side padding (1.5rem) from 40rem. Its navigation wraps. The source spacing scale is recorded above; the dossier also uses local intermediate gaps and padding.

Dossier facts use two equal columns, while record metadata pairs labels with flexible values. At 600px and below, both become a single column, search fields stack, and section spacing contracts. Section links and actions wrap. Ledger entries are separated by rules, with each title preceding its metadata and preview.

Long identifiers wrap; JSON preserves whitespace while wrapping long content inside a scrollable block. The witness table has a focusable scrolling wrapper, tabular numerals, and top-aligned cells. Its narrow layout reserves a first-column width (5rem), keeping short event names readable while identifiers and timestamps wrap.

## Elevation & Depth

The dossier's decision notice, fields, records, and checks use tonal surfaces and thin borders without box shadows. Sections and ledger entries are separated with rules rather than individually elevated cards. This describes claim inspection only; it does not redefine depth on other SAB surfaces.

## Shapes

Dossier controls and record blocks share `dossier-control` corners. Compact written states use `dossier-state` corners. Decision and runtime notices use the larger `notice` corners. Their borders are thin (1px). The incumbent primary navigation retains its pill shape; the dossier's section navigation is a row of text links between rules.

## Components

- **Primary action:** accent fill, page-canvas text, semibold weight, and a minimum height (44px). Hover applies a brightness filter (0.94). Search and dossier download actions share this treatment.
- **Search fields:** visible labels, surface fill, ink text, and a minimum height (44px). The text field and state select share the same geometry; the placeholder uses muted text at full opacity.
- **Section navigation:** wrapping text links with a minimum height (32px), a top and bottom rule, and underline on hover.
- **Decision notice:** raised surface, rounded border, compact heading, and a short explanation. Its geometry is related to the shared runtime and reliance notices.
- **Record disclosure:** native `details` and `summary` retain keyboard and no-JavaScript operation. Summaries have a minimum height (44px), change to accent on hover, and reveal full record content.
- **Checks:** each native disclosure presents its label and written state together. Rows are separated by rules; the expanded explanation sits directly below its summary.
- **JSON record:** a monospace block with preserved whitespace, wrapping, a maximum height (36rem), and contained scrolling.

Dossier links, buttons, fields, summaries, and focusable table wrappers share a visible accent outline (2px) with an offset (4px). The shell's skip link targets the main content.

**The Written State Rule.** Dossier states remain written text. Failed check states additionally use bold weight and an underline; their meaning does not depend on a colored badge.
