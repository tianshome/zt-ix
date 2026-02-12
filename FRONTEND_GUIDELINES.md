# Frontend Guidelines
Version: 0.3
Date: 2026-02-12

Related docs: `PRD.md`, `APP_FLOW.md`, `IMPLEMENTATION_PLAN.md`

## 1. Visual Direction
Marble-inspired operational console aesthetic with a plain white/light main interface: milky polished surfaces, cool mineral stone tones, and restrained warm-beige accents. The UI should feel architectural and calm while remaining precise and data-first. Blue should be reserved for small, intentional emphasis moments rather than broad, dominant UI color.

## 1.1 Runtime Model
1. Frontend is a strict SPA.
2. Browser routes are client-side only.
3. Backend integration uses fetch/XHR APIs only.
4. Backend redirect-driven page rendering is out of scope.

## 2. Typography
1. Primary UI typeface: `Noto Sans`.
2. Technical identifier typeface: `Noto Sans Mono` for `asn`, `zt_network_id`, `node_id`, and request IDs.
3. Type scale:
   - `h1`: 36px / 44px / 700
   - `h2`: 28px / 36px / 700
   - `h3`: 22px / 30px / 600
   - `body-lg`: 18px / 28px / 400
   - `body`: 16px / 24px / 400
   - `caption`: 13px / 18px / 500

## 3. Marble Palette Tokens
Use these color tokens as the canonical frontend palette:

1. Primary light surfaces (default app shell and primary content areas):
   - `surface.paperWhite`: `#FFFFFF`
   - `surface.softWhite`: `#F7FAFA`
2. Stone tones (secondary surfaces and structural tinting):
   - `stone.mistBlue`: `#C7D3D5`
   - `stone.powderBlue`: `#B5C8CD`
   - `stone.blueFog`: `#A2BBC2`
3. Depth tones (text, navigation, structural UI):
   - `depth.graphiteSlate`: `#656F70`
   - `depth.deepTealSlate`: `#5D7B87`
   - `depth.harborBlue`: `#71959E`
4. Warm-beige accent veining (primary accents and callouts):
   - `vein.clay`: `#9D8877`
   - `vein.taupe`: `#8D7B6F`

## 4. Color and Surface Behavior
1. Main interface backgrounds and primary content surfaces default to `#FFFFFF` (or `#F7FAFA` where subtle separation is needed).
2. Warm-beige accent colors (`#9D8877`, `#8D7B6F`) are the primary accent system, used for key callouts, high-value emphasis, and selected/active states where appropriate; total warm-accent usage should remain under approximately 10% of visible UI.
3. Blue tones are used sparingly for small emphasis moments (for example link text, minor status highlights, subtle focus rings), avoiding large blue fills or dominant blue navigation treatments.
4. Cards and secondary surfaces remain light-first; optional stone tints (`#A2BBC2`, `#B5C8CD`) should be used sparingly for visual grouping, with soft borders.
5. Body text defaults to `#656F70` on white/light surfaces and must pass accessibility contrast requirements.
6. Prefer subtle mineral gradients (for example `#FFFFFF -> #B5C8CD`) only on secondary surfaces; keep the main shell plain light.
7. Use thin borders (`1px`) and soft shadows to create polished depth without heavy contrast.

## 5. Spacing Scale
1. `--space-1`: 4px
2. `--space-2`: 8px
3. `--space-3`: 12px
4. `--space-4`: 16px
5. `--space-5`: 24px
6. `--space-6`: 32px
7. `--space-7`: 48px
8. `--space-8`: 64px

## 6. Layout Rules
1. Max content width: 1200px centered.
2. Desktop shell: left nav (240px), content panel, top status bar.
3. Mobile shell: top nav + slide-over menu.
4. Card radius: 12px.
5. Input/button radius: 10px.
6. Border width: 1px default, 2px on active focus.

## 7. Components
1. Buttons:
   - Primary: `vein.clay` background with light text and `vein.taupe` hover state.
   - Secondary: `surface.paperWhite` background, `stone.mistBlue` border, `depth.graphiteSlate` text.
2. Status badges:
   - Use light surfaces with thin borders and `depth.*` text as default treatment.
   - Reserve blue (`depth.harborBlue`) for minor informational emphasis only.
3. Tables:
   - Sticky header.
   - Row hover tint uses `surface.softWhite`; optional stone tint overlays are subtle.
   - Use shadcn/Radix data-table primitives for MVP admin/operator tables in `v0.1.0`.
4. Forms:
   - Label always visible above control.
   - Validation/error messaging should remain readable on light surfaces and use restrained contrast treatments that fit the palette.

## 8. Motion
1. Page enter: 180ms fade+translate (0->8px to 0).
2. List row stagger on initial render: 30ms interval up to 8 rows.
3. Disable decorative animation under `prefers-reduced-motion`.

## 9. Responsive Breakpoints
1. `sm`: 640px
2. `md`: 768px
3. `lg`: 1024px
4. `xl`: 1280px

## 10. Data Refresh
1. Request and queue status refresh uses HTTP GET polling only in `v0.1.0`.
2. Polling cadence should be bounded and configurable in frontend constants.
3. WebSocket/SSE streaming is deferred.

## 11. Accessibility Scope
1. `v0.1.0` scope: readable status text and visible keyboard focus on critical controls.
2. Full a11y hardening (contrast audits, automated tooling gates, deep screen-reader QA) is deferred post-`v0.1.0`.
