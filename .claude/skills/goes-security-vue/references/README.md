# goes-security-skill-vue

A Claude Code skill that **generates, runs, and reports automated security tests** for **Vue 3 + Vitest + Playwright** projects, aligned with the **GOES Cybersecurity Checklist** (frontend items), **OWASP Top 10 (2021)**, and **Vue-specific frontend controls** (VF1-VF12).

The output is **two self-contained files** — an interactive HTML report and an Excel workbook with one sheet per bucket — designed for compliance audits in government environments. No Java. No Allure. Pure Node.js.

This skill goes beyond test generation: it applies a series of **hardening practices to the project itself** (no-emojis policy, login card design, ThemeToggle variant, paginated catalogs, brand centralization, ESLint ignores for vendored reporter, Husky guardrails, etc.) — every rule was learned auditing a real MINEDUCYT SPA.

---

## How it works

1. The user copies the `.claude/` folder from this repo into a Vue 3 project.
2. In Claude Code, the user types a short trigger like *"Generate security tests for this project with the goes-security-testing-vue skill"*.
3. Claude reads `SKILL.md`, exhaustively maps the project's security surface (stores, composables, router guards, interceptors, components, views, `main.ts`, env config — not just `*.service.ts`), and generates one `.security-html.spec.ts` per relevant area with full metadata (epic, feature, story, severity, GOES + OWASP + VF tags, input/output evidence).
4. Claude installs the missing dev deps (`vitest`, `@vue/test-utils`, `jsdom`, `xlsx`, optionally `@playwright/test`), configures Vitest with the bundled custom reporter, and runs the suite.
5. The output is two files at `reports/security/`:
   - `security-report.html` — interactive single-file report (sidebar, modal, charts, dark theme).
   - `security-report.xlsx` — workbook with one sheet per bucket (Pasados / Desactivados / Migrados / No aplicables), ready as audit annex.

The bundled reporter is pure Node.js JavaScript (CommonJS, `.cjs` extension to coexist with Vite's `"type": "module"` packages).

---

## Installation

```bash
# 1. Clone this repo
git clone https://github.com/goes-tools/goes-security-skill-vue.git

# 2. Copy .claude/ into your Vue project
cp -r goes-security-skill-vue/.claude /path/to/your-vue-project/.claude

# 3. Open Claude Code in that project
cd /path/to/your-vue-project
claude
```

Then in Claude Code:

```
Generate security tests for this project with the goes-security-testing-vue skill.
```

That's it. The skill auto-activates on phrases like *"security tests Vue"*, *"GOES checklist frontend"*, *"pentest tests frontend"*, *"security report Vue"*, *"hardening Vue SPA"*, etc.

---

## Usage

The skill is invoked with a short prompt in Claude Code. There are **two modes** — pick the one that fits your context:

### Mode 1 — Audit-only (recommended for compliance, institutional pilots)

Claude **only generates and runs tests**. If a test fails, it stays red as a finding. Claude does **not** touch your application code (`src/`). The team decides whether to fix the source or accept the risk.

```
Generá tests de seguridad para este proyecto con el skill goes-security-testing-vue.
Aplicá las reglas críticas del SKILL.md (16 patterns, 13 unit + 3 E2E, evidence
input/output con el sufijo entre paréntesis, narrativa Prepare/Execute/Verify,
descriptionHtml con link a owasp.org, not-applicable spec exhaustivo).

NO modifiques código fuente del proyecto (src/) para hacer pasar tests. Si un
test falla, dejalo rojo y reportalo como hallazgo — el equipo decide si arreglar
el código o aceptar el riesgo. Solo podés tocar tests/security/, tests/e2e/,
package.json (scripts/devDeps), vitest.security.config.ts, playwright.config.ts,
.env.example y eslint.config.js (ignores).

Reporter:
- projectName: "GOES — [Sistema]"
- reportTitle: "Security Test Report — GOES [Sistema]"

Al final, npm run test:security y resumen con cobertura, hallazgos rojos,
items N/A con su justificación, y los 4 buckets del Excel.
```

**Use when**: you want a clean compliance report, a third-party audit, or a baseline before the team starts remediation. Findings stay visible in the HTML and Excel.

### Mode 2 — Standard (lets Claude suggest and apply fixes)

Claude generates the tests **and may also propose or apply fixes** to the source code if it identifies straightforward gaps (missing route guard, leaking `console.log`, autocomplete on a password field, missing v-html sanitization, etc.). Useful during active development.

```
Generate security tests for this project with the goes-security-testing-vue skill.

Reporter:
- projectName: "GOES — [System Name]"
- reportTitle: "Security Test Report — GOES [System Name]"
```

**Use when**: you are actively developing the project and want Claude to help close gaps as it finds them. Note that fixes applied this way should still be reviewed in PR before merging.

### Minimal trigger

```
Generate security tests for this project with the goes-security-testing-vue skill.
```

The skill reads `SKILL.md`, scans the project, generates tests, configures Vitest + Playwright, runs the suite, and produces both reports. `projectName` defaults to the value in `package.json#name`. By default this falls under Mode 2 (standard).

### Replace `[Sistema]` / `[System Name]`

In every prompt above, replace the placeholder with the real project name (e.g. `"GOES — Portafolio IT"`, `"GOES — Sistema de Trámites"`).

### Targeted regeneration

```
Regenerate the auth-store and router-guards specs with the goes-security-testing-vue skill.
```

```
Add the build/source audit and JWT payload specs (patterns 13 and 14) with the
goes-security-testing-vue skill.
```

### Run the report

After Claude configures the skill, `package.json` has these scripts:

```bash
npm run test:security    # security suite (unit) + HTML + Excel report
npm run test:e2e         # Playwright E2E suite (requires backend on /api)
npm run test:unit        # only the regular unit tests
```

The reports land at `reports/security/security-report.html` and `reports/security/security-report.xlsx` — open the HTML in any browser, no server needed. Self-contained (CSS, JS, data inline) so you can email it, attach it to a Jira ticket, or zip it as a compliance annex.

---

## What the HTML report includes

### Header

- Project name and report title (configurable).
- **Generation timestamp** in `es-SV` locale (e.g. `28/04/2026, 14:35:00`) for audit traceability.
- Reporter version.

### Interactive charts

Two SVG charts (not images) with native tooltips and click-to-filter:

- **Test Status** — donut chart (passed / failed / skipped). Click a slice to filter the table to those tests.
- **Severity Distribution** — bar chart by `blocker / critical / high / normal / minor / trivial / skipped`. Click a bar to filter.

A filter pill appears next to "Test Results" when a chart filter is active, with a clear button.

### Sidebar navigation

Tree of `Epic → Feature → Story` derived from test metadata. **Collapsed by default** (▶ to expand). Each entry shows the test count and a pass/fail indicator. Sidebar search filters the tree (does not affect the test table).

### Test results table

- Sortable by severity by default.
- Per-row badges: severity (or **N/A**) + GOES / OWASP / VF tags.
- Status icon (✓ pass · ✗ fail · ⊘ skipped).
- A second search box (**"Filter test results..."**) above the table filters only the rows below.
- Fade-in animation when filtering.

### Test detail modal

Click any row to open. Contents:

- **Spec file path** rendered under the title (`tests/security/<file>.spec.ts`) so an auditor can jump directly to the source of any assertion.
- Severity + tags badges, with `OWASP A03`, `GOES R9`, `VF8` and similar styled distinctively.
- **Not Applicable callout** if the test was tagged `N/A` — yellow stripe with the verifiable reason.
- **Classification** (Epic / Feature / Story / Owner).
- **Description** (HTML allowed) with the canonical OWASP link inline.
- **Steps** (numbered, in `Prepare / Execute / Verify` style).
- **Evidence** — JSON evidence with syntax highlighting. Tests follow an `input + output` convention: every test registers at minimum one entry capturing the attacker payload/request and one capturing the defense result/store state.
- **References** — automatic links to OWASP documentation derived from tags. `OWASP-A03` → `owasp.org/Top10/A03_2021-Injection/`. Custom links via `t.link()` are appended.
- **Errors** — full failure messages with stack traces (when status is failed).
- **Reproducibility** — file path (relative), test name, and exact `npm` command to re-run, each with a copy-to-clipboard button.
- Status footer (Status / Duration).

### Buckets

Tests are classified into 4 buckets, surfaced both as filterable sections in the HTML and as separate sheets in the Excel:

| Bucket | Criterion |
|---|---|
| **Pasados** | Tests that ran and passed — control implemented and verified |
| **Desactivados** | Tests with `.skip()` that still carry metadata — control temporarily disabled |
| **Migrados** | Tests tagged `Migrado` — control that used to apply and now lives in another layer |
| **No aplicables** | Tests tagged `N/A` — controls outside the SPA's scope |

### Search, filtering, export

- **Sidebar search** — filters the category tree.
- **Tests search** — filters the result table.
- **Chart click** — filters by status or severity.
- **Filter pill** — clears any chart filter.
- **PDF export** — `Cmd/Ctrl+P` produces a print layout with header, charts, stats, and per-test detail visible. Suitable as an audit annex.

### Visual

- Dark theme.
- Smooth animations (chart hover, row fade-in).
- Native page scroll — sidebar is sticky, the rest scrolls.
- Responsive grid for stat cards.

---

## What the Excel report includes

The same data as the HTML, structured for spreadsheet workflows that auditors and compliance teams already use:

- **One sheet per bucket** — `Pasados`, `Desactivados`, `Migrados`, `No aplicables`.
- **One row per test**, with columns for: Epic · Feature · Story · Severity · Tags (GOES / OWASP / VF) · Description · Status · Duration · **Archivo** (spec path) · Steps · Evidence (input + output, JSON-stringified).
- **Ready to copy/paste** into the regulatory annex template — each row from the *No aplicables* sheet maps directly to the GOES checklist row that justifies why a control does not apply to this SPA.

---

## What the skill applies beyond tests — hardening rules

Auditing a real SPA taught us that good security testing alone is not enough — the surrounding project conventions matter. The skill enforces these **hardening rules** when generating / reviewing code (full detail in `SKILL.md` PASO 8):

| Rule | Why |
|------|-----|
| **No emoji icons — use Lucide** | Emojis render inconsistently across OS and locales; Lucide inherits the theme color and scales as vectors. |
| **Login: card design + show-password + dark mode tokens** | The default Vite scaffold is too plain; auditors expect a polished entry point. |
| **`ThemeToggle` with `variant` prop** (`topbar` \| `default`) | One palette doesn't fit both navy topbars and surface headers — the toggle must be visible everywhere. |
| **Paginated catalogs** (search + page-size, client-side for small ones) | < few hundred rows: client-side. Larger: server-side via `?page=&limit=&search=`. |
| **`/auth/logout` is public on the BE** | A user with an expired access token must still be able to log out cleanly — guard would brick them. |
| **`@ts-expect-error` always with description ≥ 3 chars** | Otherwise lint-staged aborts the commit (`ban-ts-comment` rule). |
| **`tests/security/reporter/**` excluded from ESLint** | Vendored 3rd party — do not lint vendored code. |
| **`/reports` in `.gitignore`** | Generated artefact, regenerated each run. |
| **Brand centralization in `@/app/config/branding.ts`** | One-line rebrand. |
| **Exhaustive N/A spec** | Auditor copies/pastes each row from the Excel directly into the regulatory annex — silence is not an option. |
| **`descriptionHtml` always with OWASP link** | The HTML report links directly to canonical control documentation. |
| **`VITE_*` is **never** secret** | Every `VITE_*` ends up embedded in the production bundle — covered by pattern 13. |

---

## Coverage

### GOES Cybersecurity Checklist — frontend items

| Category | Items | Covered by |
|---|---|---|
| Web Content | R3, R4, R5, R6 | Patterns 03, 13 (R6 typically N/A on the SPA — server-served) |
| Server I/O | R8, R10, R11 | Patterns 07, 13, 03 |
| Auth & Sessions | R9, R13, R20, R21, R22, R23, R24, R32, R33, R34, R35, R40 | Patterns 01, 02, 04, 05, 06, 11, 14, 16 |
| Configuration | R42, R43, R44, R50 | Patterns 07, 13 (CSP + Cache-Control typically N/A — server-served) |
| Vue-specific (VF1-VF12) | VF1-VF12 | All applicable patterns |

### OWASP Top 10 (2021) — frontend mapping

A01 (Broken Access Control), A02 (Cryptographic Failures), A03 (Injection), A04 (Insecure Design), A05 (Security Misconfiguration), A07 (Auth Failures), A09 (Logging Failures).

A06 (Vulnerable Components), A08 (Data Integrity), and A10 (SSRF) are partially covered or on the roadmap.

### Test patterns — 16 patterns (13 unit + 3 E2E)

The skill ships with 16 reusable patterns under [references/test-patterns/](.claude/skills/goes-security-vue/references/test-patterns/):

| # | Pattern | Controls | OWASP |
|---|---------|----------|-------|
| 01 | Auth store RBAC | R9, R34, VF7 | A01 |
| 02 | Router guards | R9, R21, R24, VF8 | A01 |
| 03 | Client sanitize (v-html, DOMPurify) | R5, R11, VF1 | A03 |
| 04 | API client defaults (axios, withCredentials, baseURL) | R40, VF3 | A04, A07 |
| 05 | Refresh coordinator | R32 | A07 |
| 06 | Session + activity (idle scheduler) | R35, R40 | A04, A07 |
| 07 | Auth service errors + open redirect + storage audit | R8, R14, R42, VF12 | A01, A02, A07 |
| 08 | PERMISOS matrix + v-html sweep + autocomplete hygiene | R9, R11, R14, VF1, VF11 | A01, A03, A07 |
| 09 | Not applicable / scope boundaries | server-side controls | — |
| 10 | E2E auth flow (Playwright) | R8, R14, R42, VF12 | A01, A07 |
| 11 | E2E RBAC enforcement (Playwright) | R9, R24, R34 | A01 |
| 12 | E2E session lifecycle (Playwright) | R35, R40, VF4 | A04, A07 |
| 13 | Build / source audit — `console.log`, secrets, `VITE_*` | R3, R10, VF6, VF10 | A05, A09 |
| 14 | JWT payload safety | R20 | A02 |
| 15 | Interceptor 403 handling | VF5 | A01 |
| 16 | IDOR via URL params | R23 | A01 |

Patterns 10-12 require Playwright; the rest run on Vitest + jsdom.

---

## What a generated test looks like

Excerpt from a real spec produced by the skill — pattern 01 (`auth-store.security-html.spec.ts`):

```typescript
it('[R9] clearSession wipes accessToken, user, roles and timestamps', async () => {
  const t = report()
  t.epic('Session Management')
  t.feature('Logout hygiene')
  t.story('clearSession wipes ALL auth state')
  t.severity('critical')
  t.tag('Pentest', 'OWASP-A07', 'GOES-R9')
  t.descriptionHtml(
    '<p>A logout must leave the store identical to its initial state...</p>' +
    '<p><strong>Reference:</strong> ' +
    '<a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" ' +
    'target="_blank" rel="noopener">OWASP A07</a>.</p>',
  )

  t.step('Prepare: populate the store with a fully authenticated session')
  const auth = useAuthStore()
  const authenticated = session()
  auth.setSession(authenticated)
  t.evidence('Session before logout (input)', {
    accessToken: authenticated.accessToken,
    user: authenticated.user,
    isAuthenticated: auth.isAuthenticated,
  })

  t.step('Execute: call auth.clearSession()')
  auth.clearSession()

  t.step('Verify: every sensitive slot is back to its initial value')
  expect(auth.isAuthenticated).toBe(false)
  expect(auth.accessToken).toBeNull()
  // ... 4 more assertions

  t.evidence('Store snapshot after clearSession (output)', {
    accessToken: auth.accessToken,
    user: auth.user,
    roles: auth.roles,
    isAuthenticated: auth.isAuthenticated,
  })

  await t.flush()
})
```

Note the **`(input)` / `(output)` suffix between parentheses** — required convention so the HTML modal renders evidence consistently with the BE skill output.

---

## Marking items as Not Applicable

When a checklist item does not apply to the project (e.g. password hashing on a SPA that never stores passwords, server-side rate limiting, file upload rules when no upload UI exists), do **not** use silent omission or `it.skip()` without metadata. Use the `not-applicable.security-html.spec.ts` spec (pattern 09):

```typescript
it('[GOES-R15] Password hashing — N/A on the SPA', async () => {
  const t = report()
  t.epic('Auth & Sessions')
  t.feature('Password Storage')
  t.story('Backend-only control')
  t.severity('blocker')
  t.tag('N/A', 'GOES-R15', 'OWASP-A02')

  t.notApplicable(
    'The SPA never receives plaintext passwords for storage. The login form ' +
    'submits credentials over HTTPS to /auth/login on the backend, which ' +
    'hashes them with bcrypt (cost 12). No password ever lives in Pinia, ' +
    'localStorage, or sessionStorage. Verifier: grep -r "bcrypt" backend/src/.',
  )

  await t.flush()
})
```

Such tests render as **skipped** (⊘) with a **N/A** badge in the row, a yellow callout in the modal explaining why, and land in the **No aplicables** sheet of the Excel. They preserve full GOES traceability — the auditor sees explicitly that the control was considered, evaluated, and ruled out of scope, with a verifiable reason.

---

## Reporter customization

Pass options to the bundled reporter in `vitest.security.config.ts`:

```typescript
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import path from 'node:path'

const reporterPath = path.resolve(
  __dirname,
  '.claude/skills/goes-security-vue/reporter',
)

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@security-reporter': reporterPath,
    },
  },
  test: {
    environment: 'jsdom',
    include: ['tests/security/**/*.security-html.spec.ts'],
    reporters: [
      'default',
      [path.join(reporterPath, 'html-reporter.cjs'), {
        outputPath: './reports/security/security-report.html',
        projectName: 'GOES — Portafolio IT',     // optional, falls back to package.json#name
        reportTitle: 'Security Test Report — GOES',  // optional
      }],
    ],
  },
})
```

Two environment variables help in CI / parallel runs:

| Variable | Purpose |
|---|---|
| `SECURITY_REPORTER_RUN_ID` | Subdir per run under `$TMPDIR/security-html-reporter/<runId>` — required when running Vitest with multiple workers or when several CI jobs share a runner. |
| `SECURITY_REPORTER_TEMP_DIR` | Full override of the metadata tempdir (use it when you need the metadata under your CI workspace). |

### Why `.cjs` and not `.js`?

Projects scaffolded with `create-vue` / Vite ship `"type": "module"` in `package.json`. Under that flag Node treats every `.js` as ESM; Vitest custom reporters are CommonJS. The `.cjs` extension forces CJS parsing unconditionally — the reporter loads the same way regardless of the host project's module mode.

---

## Architecture

```
.claude/skills/goes-security-vue/
├── SKILL.md                          ← instructions for Claude
├── reporter/
│   ├── html-reporter.cjs             ← Vitest custom reporter (~2200 lines, JS, CJS)
│   └── metadata.ts                   ← metadata collector + AllureCompat
└── references/
    ├── goes-checklist.md             ← GOES checklist (frontend items) + VF1-VF12
    └── test-patterns/                ← 16 patterns + 3 support files
        ├── _setup.md
        ├── _severity-guide.md
        ├── _playwright-setup.md
        ├── 01-auth-store-rbac.md
        ├── 02-router-guards.md
        ├── 03-client-sanitize.md
        ├── 04-api-client-defaults.md
        ├── 05-refresh-coordinator.md
        ├── 06-session-activity.md
        ├── 07-auth-service-errors.md
        ├── 08-permissions-matrix-vhtml-autocomplete.md
        ├── 09-not-applicable.md
        ├── 10-e2e-auth-flow.md
        ├── 11-e2e-rbac.md
        ├── 12-e2e-session-lifecycle.md
        ├── 13-build-source-audit.md
        ├── 14-jwt-payload-safety.md
        ├── 15-interceptor-403-handling.md
        └── 16-idor-url-params.md
```

The reporter consists of two files:

- **`reporter/html-reporter.cjs`** — Vitest custom reporter (pure JavaScript, CommonJS, ~2200 lines). Supports Vitest v4 (`onTestRunEnd`) with fallback for v3 (`onFinished`) and Jest legacy (`onRunComplete`). Reads metadata JSON files written by tests, merges with Vitest results, generates the self-contained HTML and the Excel via `xlsx` (SheetJS).
- **`reporter/metadata.ts`** — metadata collector. Exposes `report()` and `AllureCompat`. Each test registers epic, feature, story, severity, tags, parameters, steps, and evidence.

---

## Requirements

- **Vue 3** project (Vite-based recommended)
- **Node.js 18+**
- **Vitest** configured (or Claude installs it)
- **`xlsx` (SheetJS)** as devDependency — Claude installs it automatically
- **Playwright** *optional* — only required for patterns 10-12 (E2E). After `npm install`, run `npx playwright install` once (~150 MB) to fetch the browser binaries.
- **Claude Code** (or Claude Cowork) for skill activation

No Java required.

---

## Changelog

### v1.2 (2026-05)

**Reporter parity with the BE skill**
- **Bundled reporter is now `.cjs`** — coexists with Vite's `"type": "module"` packages without `__esModule` interop hacks.
- **Vitest v4 support** — primary entry point is `onTestRunEnd`, with backward-compatible fallbacks for v3 (`onFinished`) and Jest legacy (`onRunComplete`).
- **Excel workbook output** — `security-report.xlsx` generated alongside the HTML via `xlsx` (SheetJS), one sheet per bucket (`Pasados / Desactivados / Migrados / No aplicables`).
- **Spec file path in the modal** — every test detail now shows `tests/security/<file>.spec.ts` under the title, with copy-to-clipboard, so an auditor can jump directly to the source.
- **Evidence naming convention enforced** — labels must end with `(input)` / `(output)` between parentheses for visual parity with the BE report. The skill rejects `Input - …` / `Output - …` prefixes.
- **Metadata enhancements** — richer per-test fields (owner, severity rationale, GOES + OWASP + VF tags coexist cleanly).

**Skill rules (SKILL.md)**
- **16 patterns** — 13 Vitest unit + 3 Playwright E2E. New patterns: build/source audit (13), JWT payload safety (14), interceptor 403 handling (15), IDOR via URL params (16).
- **Audit-only mode (opt-in via prompt)** — when the prompt asks Claude not to modify `src/`, failing tests stay red as findings; the team decides whether to remediate.
- **Hardening rules (PASO 8)** — no-emoji policy (Lucide only), login card design, `ThemeToggle` with `variant` prop (`topbar` | `default`), paginated catalogs, `/auth/logout` public on BE, `@ts-expect-error` description requirement, ESLint ignores for vendored reporter, `/reports` in `.gitignore`, brand centralization in `@/app/config/branding.ts`.
- **Exhaustive N/A spec required** — `not-applicable.security-html.spec.ts` documents every checklist item that does not apply to the SPA, with verifier (`grep`, BE file path, etc.).

### v1.1 (2026-04)

- **Zero-config setup** — the reporter lives at `.claude/skills/goes-security-vue/reporter/` and is referenced directly from `vitest.security.config.ts`. No file duplication into `tests/security/reporter/`.
- **README profesional** generated for the host project (RBAC matrix, env vars, scripts, seeded credentials, suite-of-security table).
- **Buckets** added: Pasados / Desactivados / Migrados / No aplicables.
- **Migration from Allure to custom reporter** — no Java, no `allure-vitest`, no `allure-commandline`. Pure Node.js.
- **Path alias `@security-reporter`** in `vitest.security.config.ts` for cleaner imports inside specs.

### v1.0

- Initial release with custom HTML reporter, 12 patterns, GOES frontend checklist, OWASP Top 10 mapping.

---

## Roadmap

Items currently out of scope or partially covered, planned for future versions:

- **A10 SSRF** test pattern (frontend mapping — open redirect deepening).
- **A06 Vulnerable Components** — `npm audit` / `osv-scanner` hook integrated into the report.
- **A08 Data Integrity** — Subresource Integrity (SRI) audit for `<script>` / `<link>` tags.
- **CSP report-only** — pattern that asserts `<meta http-equiv="Content-Security-Policy">` posture (when served via `index.html` instead of headers).
- **Framework adapters** beyond Vue (React, Angular, Svelte, Nuxt SSR).
- **Baseline / diff** between runs to highlight regressions.
- **SARIF export** for GitHub Code Scanning / GitLab Security Dashboard ingestion.
- **Severity gates** in CI (e.g. `failOn: 'blocker'`).
- **ISO 27001 / NIST 800-53** mapping in the GOES checklist.

---

## Companion skill — backend

For the **NestJS backend equivalent**, see [goes-security-skill](https://github.com/goes-tools/goes-security-skill).

Both skills share the same reporter architecture and metadata model. Running one project with both skills (BE + FE) produces consistent, comparable audit reports across the stack — same buckets, same OWASP mapping, same JSON evidence format, same modal layout.

---

## Contributing

Pull requests are welcome for:

- New test patterns in [`references/test-patterns/`](.claude/skills/goes-security-vue/references/test-patterns/) — especially the roadmap gaps above.
- Updates to the checklist in [`references/goes-checklist.md`](.claude/skills/goes-security-vue/references/goes-checklist.md).
- Improvements to skill instructions in [`SKILL.md`](.claude/skills/goes-security-vue/SKILL.md).
- Support for other frontend frameworks (React, Angular, Svelte, Nuxt).

### How to contribute

1. Fork the repo.
2. Create a branch: `git checkout -b feature/new-pattern`.
3. Make changes.
4. Open a PR with a description of what was added or changed.

---

## License

Internal use — Government of El Salvador (GOES) · MINEDUCYT.
