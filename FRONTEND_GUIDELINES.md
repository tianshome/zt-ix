# Frontend Guidelines
Version: 0.2
Date: 2026-02-11

Related docs: `PRD.md`, `APP_FLOW.md`, `IMPLEMENTATION_PLAN.md`

## 1. Visual Direction
Operational-console aesthetic: clean, high-contrast, and data-first. The UI should feel precise and network-centric rather than marketing-oriented.

## 1.1 Runtime Model
1. Frontend is a strict SPA.
2. Browser routes are client-side only.
3. Backend integration uses fetch/XHR APIs only.
4. Backend redirect-driven page rendering is out of scope.

## 2. Typography
1. Primary UI font: `Sora`
2. Secondary/reading font: `Source Sans 3`
3. Monospace for technical identifiers (ASN, network/member IDs): `IBM Plex Mono`
4. Type scale:
   - `h1`: 36px / 44px / 700
   - `h2`: 28px / 36px / 700
   - `h3`: 22px / 30px / 600
   - `body-lg`: 18px / 28px / 400
   - `body`: 16px / 24px / 400
   - `caption`: 13px / 18px / 500

## 3. Color Palette (Exact Hex)
1. `--bg-canvas`: `#F3F7FA`
2. `--bg-panel`: `#FFFFFF`
3. `--bg-panel-alt`: `#EAF1F6`
4. `--text-primary`: `#102331`
5. `--text-secondary`: `#3A5364`
6. `--border-default`: `#C9D7E2`
7. `--accent-primary`: `#0A7A5A`
8. `--accent-primary-hover`: `#08684C`
9. `--accent-info`: `#006AAE`
10. `--status-success`: `#0E8A5A`
11. `--status-warning`: `#CC7A00`
12. `--status-error`: `#C0392B`
13. `--status-pending`: `#6C7A89`

## 4. Spacing Scale
1. `--space-1`: 4px
2. `--space-2`: 8px
3. `--space-3`: 12px
4. `--space-4`: 16px
5. `--space-5`: 24px
6. `--space-6`: 32px
7. `--space-7`: 48px
8. `--space-8`: 64px

## 5. Layout Rules
1. Max content width: 1200px centered.
2. Desktop shell: left nav (240px), content panel, top status bar.
3. Mobile shell: top nav + slide-over menu.
4. Card radius: 12px.
5. Input/button radius: 10px.
6. Border width: 1px default, 2px on active focus.

## 6. Components
1. Buttons:
   - Primary: `--accent-primary` background, white text.
   - Secondary: white background, `--border-default` border, `--text-primary`.
2. Status badges:
   - `pending`: gray
   - `approved/provisioning`: info blue
   - `active`: success green
   - `failed/rejected`: error red
3. Tables:
   - Sticky header
   - Row hover tint using `--bg-panel-alt`
   - Use shadcn/Radix data-table primitives for MVP admin/operator tables in `v0.1.0`
4. Forms:
   - Label always visible above control
   - Inline error under field in `--status-error`

## 7. Motion
1. Page enter: 180ms fade+translate (0->8px to 0).
2. List row stagger on initial render: 30ms interval up to 8 rows.
3. Disable decorative animation under `prefers-reduced-motion`.

## 8. Responsive Breakpoints
1. `sm`: 640px
2. `md`: 768px
3. `lg`: 1024px
4. `xl`: 1280px

## 9. Data Refresh
1. Request and queue status refresh uses HTTP GET polling only in `v0.1.0`.
2. Polling cadence should be bounded and configurable in frontend constants.
3. WebSocket/SSE streaming is deferred.

## 10. Accessibility Scope
1. `v0.1.0` scope: readable status text and visible keyboard focus on critical controls.
2. Full a11y hardening (contrast audits, automated tooling gates, deep screen-reader QA) is deferred post-`v0.1.0`.
