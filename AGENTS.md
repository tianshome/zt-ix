# AGENTS.md

This repository is built to be worked on with AI agents _without_ devolving into inconsistency, hallucinated requirements, or architecture drift. The system is **docs first, code second**.

## 0) Non-negotiables

1. **Docs before code. Always.**
   - Do not write or modify implementation code until you have read the project’s spec docs (see §1).
2. **No assumptions. Interrogate ambiguity.**
   - If anything is underspecified, ask questions (or write an explicit assumption list and get it approved) before implementing.
3. **One source of truth.**
   - Requirements live in PRD/flows; design lives in frontend guidelines; data/contracts live in backend structure; sequence lives in implementation plan.
4. **No “creative” tech choices.**
   - You may not introduce libraries, frameworks, patterns, or versions not explicitly allowed by TECH_STACK.md.
5. **Progress must persist.**
   - Update `progress.txt` after every meaningful change so the next session does not restart from zero context.

## 1) Required documents (read in this order)

Agents must read these files at the start of each work session:

1. `AGENTS.md`
2. `progress.txt`
3. `PRD.md`
4. `APP_FLOW.md`
5. `TECH_STACK.md`
6. `FRONTEND_GUIDELINES.md`
7. `BACKEND_STRUCTURE.md`
8. `IMPLEMENTATION_PLAN.md`
9. `lessons.md` (if present)

If any of these are missing, create a **stub** with headings and TODOs rather than guessing.

## 2) Operating loop (how you work)

### Step A — Interrogate (Planning mode)

Before coding, force clarity:

- Who is the user? What is the core action?
- What data is created/updated/read?
- What happens on success/failure?
- What are edge cases, auth needs, mobile needs, error states?
- What is explicitly _out of scope_?

Output:

- A short “Assumptions & Open Questions” list.
- A proposed plan aligned to `IMPLEMENTATION_PLAN.md` steps.

### Step B — Plan (bounded scope)

Create a plan that:

- References the exact doc sections you’re implementing.
- Lists concrete file paths you will touch/create.
- Includes verification steps (tests, lint, manual checks).
- Avoids scope creep (only what the current step requires).

### Step C — Execute (small, reviewable increments)

Implement in small increments:

- Prefer minimal diffs.
- Keep changes local to the current step.
- Use the repo’s conventions for naming, structure, and patterns.

### Step D — Verify (prove it works)

At minimum:

- Run relevant tests (unit/integration/e2e as applicable).
- Run lint/typecheck (if configured).
- Manually sanity-check the key user flow(s) affected.

### Step E — Persist context

Update:

- `progress.txt` (completed / in-progress / next / known bugs)
- `lessons.md` (if you hit a recurring pitfall; add a rule to prevent repeats)

## 3) Scope control

Agents must **not**:

- Add features not listed in `PRD.md`.
- Invent routes, screens, or flows not in `APP_FLOW.md`.
- “Improve” architecture beyond what the current `IMPLEMENTATION_PLAN.md` step requires.
- Refactor unrelated areas unless explicitly requested or required for correctness.

If you discover missing requirements, stop and:

- Write the gap into PRD/flow docs as a proposed addition, or
- Ask for a decision.

## 4) Dependency and stack discipline

- All packages, APIs, and tooling must match `TECH_STACK.md` (including versions).
- If you believe a new dependency is necessary:
  1. Explain why, 2) propose alternatives, 3) request approval, 4) update TECH_STACK.md _only after approval_.

## 5) Frontend rules (UI consistency)

- Implement UI strictly using `FRONTEND_GUIDELINES.md`.
- Use the defined design tokens (colors, spacing scale, typography, radius, shadows, motion).
- Follow mobile-first responsive rules and breakpoints as documented.
- Separate **UI** (“how it looks”) from **UX** (“how it feels/flows”). When changing screens, state which you are improving and why.

## 6) Backend rules (data + contracts)

- Data schema and relations must match `BACKEND_STRUCTURE.md`.
- API endpoints must follow documented request/response contracts.
- Handle edge cases and error states explicitly (auth, validation, not-found, conflict, rate limits if relevant).
- Do not leak secrets to the client; keep sensitive operations server-side.

## 7) File and folder structure

Follow the repository’s canonical structure (as documented). If you must add a new folder:

- Prefer existing conventions.
- Document the new structure and why it exists.

When creating new files, always state:

- Why the file exists
- How it is used
- What doc(s) it implements

## 8) Secrets and environment variables

- Never commit `.env` files.
- Never paste secrets into chat, issues, or logs.
- Use environment-variable access patterns consistent with the project.
- If a secret is suspected compromised, treat it as leaked and rotate it.

## 9) Git hygiene (if you are committing)

- Commit in small, meaningful chunks.
- Commit message format: `<scope>: <what changed>`
  - Examples: `auth: add session refresh`, `ui: align card spacing tokens`, `api: validate payload`
- Keep `progress.txt` updated in the same PR/commit series where possible.

## 10) What to deliver in each response

When you finish a task, report:

1. **What changed** (high level)
2. **Files touched** (paths)
3. **How it maps to docs** (which PRD/flow/plan step)
4. **Verification performed** (commands/tests/manual checks)
5. **Next steps** (what remains, risks, known bugs)

---

## Appendix: Minimal templates

### progress.txt template

- Completed:
- In progress:
- Next:
- Known bugs / regressions:
- Notes (constraints learned, pitfalls):

### lessons.md template

- Symptom:
- Root cause:
- Rule to prevent recurrence:
- Example (good vs bad):
