# goes-security-skill-vue

Claude skill for generating automated security tests with a **Custom HTML + Excel Reporter** for **Vue 3 + Vitest + Playwright** projects.

No Java, no Allure — pure Node.js reporter that generates a self-contained HTML file (sidebar navigation, charts, evidence highlighting, bucket classification) plus an Excel workbook ready for regulatory evidence.

Covers the **GOES Cybersecurity Checklist** (frontend items), **OWASP Top 10**, and Vue-specific controls (VF1-VF12).

---

## Installation

### 1. Clone this repo

```bash
git clone https://github.com/goes-tools/goes-security-skill-vue.git
```

### 2. Copy the `.claude/` folder to your Vue project

```bash
cp -r goes-security-skill-vue/.claude/ /path/to/your-vue-project/.claude/
```

Your project structure will look like:

```
your-vue-project/
  .claude/
    skills/
      goes-security-vue/
        SKILL.md                                <-- instructions for Claude
        reporter/
          html-reporter.cjs                     <-- custom HTML + Excel reporter (bundled)
          metadata.ts                           <-- metadata collector (bundled)
        references/
          goes-checklist.md                     <-- GOES checklist (frontend items) + VF1-VF12
          test-patterns/                        <-- 16 patterns + 3 support files
            _setup.md
            _severity-guide.md
            _playwright-setup.md
            01-auth-store-rbac.md
            02-router-guards.md
            03-client-sanitize.md
            04-api-client-defaults.md
            05-refresh-coordinator.md
            06-session-activity.md
            07-auth-service-errors.md
            08-permissions-matrix-vhtml-autocomplete.md
            09-not-applicable.md
            10-e2e-auth-flow.md
            11-e2e-rbac.md
            12-e2e-session-lifecycle.md
            13-build-source-audit.md
            14-jwt-payload-safety.md
            15-interceptor-403-handling.md
            16-idor-url-params.md
  src/
  package.json
  ...
```

### 3. Open Claude in your Vue project

Open **Claude Code** or **Claude Cowork** in your project folder.

### 4. Ask Claude to generate the tests

```
Generate security tests for all stores / composables / router guards using the goes-security-testing-vue skill.
Cover all GOES checklist items (frontend) with OWASP traceability, install the needed dev deps
(xlsx, vitest, jsdom, @vue/test-utils), and run the suite to generate the HTML + Excel report.
```

Claude reads the skill, analyzes your actual code (stores, composables, router, interceptors), configures Vitest + Playwright with the bundled reporter, generates the specs, runs them, and generates the HTML + Excel reports automatically.

---

## What Claude does

When you activate the skill, Claude:

1. Analyzes your views, components, stores (Pinia/Vuex), router, composables, interceptors
2. Installs dev deps if missing (`vitest`, `@vue/test-utils`, `jsdom`, `xlsx`, optionally `@playwright/test`) — no Java required
3. Configures Vitest to use the bundled reporter directly from `.claude/` (no file duplication)
4. Creates `tests/security/` with `.security-html.spec.ts` files covering the 13 unit patterns
5. Creates `tests/e2e/` with `.security.spec.ts` files covering the 3 E2E patterns (if Playwright is set up)
6. Documents out-of-scope controls in `not-applicable.security-html.spec.ts` (password hashing, rate limiting, file uploads if none exist, etc.)
7. Runs all security tests automatically
8. Generates BOTH artefacts:
   - `reports/security/security-report.html` — interactive report with buckets (Pasados / Desactivados / Migrados / No aplicables)
   - `reports/security/security-report.xlsx` — workbook with one sheet per bucket for audit annexes

---

## Usage examples

```
> Generate security tests for the auth store
> Generate security tests for the router guards
> Generate security tests for the api client + interceptors
> Generate E2E security tests (login, RBAC, session lifecycle) using Playwright
> Generate security tests for all 16 patterns + run the full suite
```

### View the report

```bash
npm run test:security
# HTML:  reports/security/security-report.html  (open directly in any browser)
# Excel: reports/security/security-report.xlsx  (one sheet per bucket)
```

Both files are self-contained and regenerated on every run. The HTML is ideal for local exploration; the Excel is ideal as an annex for security / compliance reviews.

E2E (requires backend running on `/api`):

```bash
npm run test:e2e
```

---

## Coverage

### GOES Cybersecurity Checklist — Frontend Items

| Category | Items | Covered by |
|----------|-------|------------|
| Web Content | R3, R4, R5, R6 | Patterns 03, 13; R6 usually N/A |
| Input/Output | R8, R10, R11 | Patterns 07, 13, 03 |
| Auth & Sessions | R9, R13, R20, R21, R22, R23, R24, R32, R33, R34, R35, R40 | Patterns 01, 02, 04, 05, 06, 11, 14, 16 |
| Configuration | R42, R43, R44, R50 | Patterns 07, 13; CSP + Cache-Control usually N/A (server-served) |
| Vue-specific (VF1-VF12) | VF1-VF12 | All applicable patterns |

### OWASP Top 10 — Frontend Mapping

A01 (Broken Access Control), A02 (Crypto Failures), A03 (Injection), A04 (Insecure Design), A05 (Security Misconfiguration), A07 (Auth Failures), A09 (Logging Failures)

### Test Patterns — 16 patterns

13 unit (Vitest) + 3 E2E (Playwright):

1. Auth store RBAC (R9, R34, VF7)
2. Router guards (R9, R21, R24, VF8)
3. Client sanitize (R5, R11, VF1)
4. API client defaults (R40, VF3)
5. Refresh coordinator (R32)
6. Session + activity (R35, R40)
7. Auth service errors + open redirect + storage audit (R8, R14, R42, VF12)
8. PERMISOS matrix + v-html sweep + autocomplete hygiene (R9, R11, R14, VF1, VF11)
9. Not applicable / scope boundaries
10. E2E auth flow (R8, R14, R42, VF12)
11. E2E RBAC enforcement (R9, R24, R34)
12. E2E session lifecycle (R35, R40, VF4)
13. Build / source audit — console.log, secrets, VITE_* (R3, R10, VF6, VF10)
14. JWT payload safety (R20)
15. Interceptor 403 handling (VF5)
16. IDOR via URL params (R23)

---

## Requirements

- **Vue 3** project with Vitest configured (or Claude installs it)
- **Node.js 18+**
- **No Java required** — uses a custom pure Node.js HTML + Excel reporter
- **`xlsx` (SheetJS)** installed as devDependency (for the Excel output). The skill installs it automatically on first run.
- **Playwright** optional — only required for patterns 10-12 (E2E)

---

## Contributing

PRs are welcome for:

- Adding new test patterns in `references/test-patterns/`
- Updating the checklist in `references/goes-checklist.md`
- Improving skill instructions in `SKILL.md`
- Supporting other frontend frameworks (React, Angular, Svelte)

### How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b feature/new-pattern`
3. Make changes
4. PR with description of what was added/changed

---

## Companion skill — backend

For the NestJS backend equivalent, see [goes-security-skill](https://github.com/goes-tools/goes-security-skill).

Both skills share the same reporter architecture. Running one project with both skills (BE + FE) produces consistent, comparable audit reports across the stack.

---

## License

Internal use — Government of El Salvador (GOES)
