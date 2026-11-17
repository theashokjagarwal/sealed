# SEALED — Architectural & Design Decisions (Frozen)

This document commits to the single design direction, aesthetic rules, token system, and structural decisions for **SEALED**. Every decision here is binding. Taste without decisions becomes moodboard churn.

---

## 1. Design Direction: "Instrument Panel"
- **Commitment**: Dense, calm, high-contrast, terminal-adjacent for engineers, security researchers, and auditors.
- **State-Only Accent**: Exactly one accent family used **strictly** for state (Pass = Emerald `#10b981`, Fail = Crimson `#f43f5e`, Warn = Amber `#f59e0b`, Running = Cyan `#06b6d4`, Unknown = Neutral `#71717a`). No decorative accent splashes or tinted background gradients.

---

## 2. Colour System: Day-One Dual Themes

All colours are defined as CSS tokens and never hardcoded in component declarations.

### Semantic State Tokens
- `--state-pass`: `#10b981` (Dark) / `#059669` (Light)
- `--state-fail`: `#f43f5e` (Dark) / `#e11d48` (Light)
- `--state-warn`: `#f59e0b` (Dark) / `#d97706` (Light)
- `--state-running`: `#06b6d4` (Dark) / `#0891b2` (Light)
- `--state-unknown`: `#71717a` (Dark) / `#71717a` (Light)

### Neutral Surface & Text Hierarchy
| Token | Dark Theme | Light Theme | Intent |
|---|---|---|---|
| `--bg-canvas` | `#090a0f` | `#f8f9fa` | Deep background canvas |
| `--bg-surface` | `#11131a` | `#ffffff` | Primary panel surface |
| `--bg-subtle` | `#171a23` | `#f1f3f5` | Secondary container & inputs |
| `--bg-active` | `#222634` | `#e9ecef` | Active/selected row or item |
| `--border-subtle` | `#1f2330` | `#e2e8f0` | Dividers and inactive borders |
| `--border-strong` | `#333a4d` | `#cbd5e1` | Focus indicators, card boundaries |
| `--text-primary` | `#f1f5f9` | `#0f172a` | Headers, critical values, body |
| `--text-secondary` | `#94a3b8` | `#475569` | Labels, captions, metadata |
| `--text-muted` | `#64748b` | `#64748b` | Disabled hints, keystrokes |

---

## 3. Typography: Grotesque UI + Monospace Evidence

- **Grotesque Family**: System Neo-Grotesque stack (`-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif`) for all navigation, headings, and controls.
- **Monospace Family**: System Monospace stack (`"JetBrains Mono", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace`) for all file paths, SHA-256 hashes, timestamps, probes, model outputs, and raw JSON.
- **Fixed Type Scale** (strictly observed across all components):
  - `32px` (`2rem`, line-height `1.2`, weight `600`) — Top-level section / view headers
  - `24px` (`1.5rem`, line-height `1.25`, weight `600`) — Panel headers, modal titles
  - `18px` (`1.125rem`, line-height `1.35`, weight `500`) — Card titles, finding summary
  - `15px` (`0.9375rem`, line-height `1.45`, weight `400`/`500`) — Primary body, table rows
  - `13px` (`0.8125rem`, line-height `1.4`, weight `400`/`500`) — Secondary body, table cells, controls
  - `12px` (`0.75rem`, line-height `1.3`, weight `400`/`600`) — Badges, metadata, timestamp, hashes
- **Tabular Figures**: All timestamps, duration counters, line numbers, and findings counters enforce `font-variant-numeric: tabular-nums`.

---

## 4. Spacing System: 4px Strict Base Grid

Only the following spacing steps are allowed. No arbitrary pixel values anywhere:
- `4px` (`--space-1`): Micro padding, badge inner spacing, icon-to-label gaps
- `8px` (`--space-2`): Input padding, button inner padding, list item vertical gaps
- `12px` (`--space-3`): Medium padding, toolbar item gaps
- `16px` (`--space-4`): Container padding, standard grid gap
- `24px` (`--space-6`): Major section padding, panel separation
- `32px` (`--space-8`): Large viewport gutter, modal outer margins
- `48px` (`--space-12`): Hero drop-target vertical padding, landing margins

---

## 5. Radius, Elevation, and Border Rules

- **Radius Scale**:
  - `0px` — Data tables, full-height splitters, status bars
  - `3px` — Small inline badges, keyboard shortcut chips (`<kbd>`), code spans
  - `6px` — Buttons, text inputs, selector dropdowns, finding cards
  - `8px` — Modals, panels, drop targets (Maximum allowed radius in the application)
  - `rounded-2xl` / large pill shapes are **strictly forbidden**.
- **Elevation**:
  - Zero drop shadows on regular layout cards. Separation is achieved through `--border-subtle` and `--bg-subtle` contrast.
  - Exactly one drop shadow token for elevated dialogs/flyouts: `0 8px 24px -4px rgba(0, 0, 0, 0.4)`.
- **Border Rules**:
  - 1px solid borders throughout. No thick borders except active keyboard focus rings (2px solid `--border-strong`).

---

## 6. Motion Protocol

- **Duration Scale**:
  - Instant (`0ms`): Immediate toggle states and selection indicators.
  - Micro (`100ms`): Button hover, focus transitions, accordion chevrons.
  - Standard (`200ms`): Drawer slide, panel cross-fade, findings entry slide.
  - Hard limit: No animation may exceed `250ms` (except live incoming telemetry stream).
- **Easing Family**:
  - `cubic-bezier(0.16, 1, 0.3, 1)` (Out-Expo) for entry / layout expansion.
  - `cubic-bezier(0.4, 0, 1, 1)` (In-Quad) for exits.
- **Prefers-Reduced-Motion**:
  - Under `prefers-reduced-motion: reduce`, all duration tokens resolve to `0ms`. All animations transition instantaneously.
- **Prohibitions**:
  - Zero decorative looping animations.
  - Zero pulsating hero glows.
  - Zero scroll-jacking.
  - Animations never block user keyboard or pointer interaction.

---

## 7. Voice and Tone

- **Factual, Plain, Unadorned**: The auditor is a diagnostic tool, not a sales pitch.
- **Findings Formulation**: State the violation, the tested vector, the exact file or API trigger, and the regulatory control clause.
  - *Example*: `"C-04: System prompt exfiltration succeeded via indirect injection in RAG context (knowledge/specs.txt:42). Violates EU AI Act Art. 15(1) & ISO 42001 A.8.4."`
- **Zero Jargon / Zero Marketing**: No words like "empower", "seamless", "magical", "revolutionary".

---

## 8. Anti-Slop Audit Checklist (Verified Zero Defaults)

- [x] No purple/blue gradient heroes or glowing orbs.
- [x] No glassmorphism (`backdrop-filter: blur`) or translucent illegible text.
- [x] No emoji as icons (use clean SVG line glyphs exclusively).
- [x] No lorem ipsum, no fake testimonials, no fictional partner logos.
- [x] No generic 3-card marketing columns.
- [x] No centered body text; left-aligned data display with strict measure (`max-width: 65ch` for prose).
- [x] No disabled buttons without explicit inline explanations for why they are disabled.
- [x] Every screen displays real dynamic state; comprehensive, structured empty states when data is absent.
