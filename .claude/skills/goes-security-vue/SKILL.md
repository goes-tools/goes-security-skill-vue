---
name: generate-security-tests-vue
description: >
  This skill should be used when the user asks to "generate security tests for Vue",
  "create frontend security specs", "generate GOES tests for Vue",
  "add allure tests to Vue", "create XSS tests", "security tests for frontend",
  "tests de seguridad para Vue", "crear tests de seguridad frontend",
  or any variation requesting automated security test generation for a Vue.js project.
metadata:
  version: "1.0.0"
  coverage: "Checklist GOES (items frontend) + OWASP Top 10 + Allure Report"
---

# GOES Security Test Generator — Vue.js Frontend

Generate professional security tests with Allure Report for Vue.js + Vitest projects.
Covers the GOES Cybersecurity Checklist (frontend items), OWASP Top 10, and common frontend vulnerabilities.

## Execution Flow

Follow these 6 steps in order. Do NOT skip any step.

### STEP 1: Analyze the project

Read these files to understand the project structure:

1. `package.json` — framework version, test runner, dependencies, package manager
2. Check for lock files: `pnpm-lock.yaml` (pnpm), `yarn.lock` (yarn), `package-lock.json` (npm)
3. Glob `src/views/**/*.vue` or `src/pages/**/*.vue` — list all views/pages
4. Glob `src/components/**/*.vue` — list all components
5. Glob `src/router/**/*.ts` or `src/router/**/*.js` — route definitions and guards
6. Glob `src/stores/**/*.ts` or `src/store/**/*.ts` — Pinia/Vuex stores
7. Glob `src/composables/**/*.ts` — composables (especially auth, api, etc.)
8. Glob `src/utils/**/*.ts` or `src/services/**/*.ts` — API services, interceptors
9. Check for `src/plugins/**/*.ts` — plugins (axios, auth, etc.)
10. Check if `.spec.ts` or `.test.ts` files already exist

### STEP 2: Install dependencies (if missing)

Detect the package manager from lock files:
- `pnpm-lock.yaml` → use `pnpm add -D`
- `yarn.lock` → use `yarn add -D`
- `package-lock.json` or none → use `npm install --save-dev`

Check devDependencies. Only install what is missing:

```bash
# Replace PKG_CMD with the detected package manager command
PKG_CMD add -D allure-vitest allure-js-commons allure-commandline
```

If the project uses Jest instead of Vitest, install `allure-jest` instead of `allure-vitest`.

### STEP 3: Configure Vitest + Allure

Modify `vitest.config.ts` (or `vite.config.ts` test section):

```typescript
import { defineConfig } from 'vitest/config';
import AllureReporter from 'allure-vitest/reporter';

export default defineConfig({
  test: {
    reporters: [
      'default',
      new AllureReporter({ resultsDir: 'allure-results' }),
    ],
    setupFiles: ['./test/allure-setup.ts'],
  },
});
```

Create support files:
- `test/allure-setup.ts` — copies categories to allure-results
- `allure-categories.json` — custom failure categories (XSS, Auth, Config, Product)
- Add `/allure-results`, `/allure-report` to `.gitignore`

Add scripts to `package.json`:
- `"test:security"`: run only security tests
- `"test:allure"`: run tests + generate + open Allure report
- `"allure:generate"`: generate report from results
- `"allure:open"`: open report in browser

### STEP 4: Read the actual code

Before writing ANY test, read the actual source files. Understand:
- Every component that handles user input (forms, search, comments)
- Router configuration: guards, meta fields, protected routes
- Store/composable that handles auth (tokens, user state, permissions)
- API service/interceptor (how requests are made, error handling)
- Any use of `v-html`, `innerHTML`, or dynamic content rendering
- Environment variables usage (what's exposed to client)
- Cookie handling, localStorage/sessionStorage usage

### STEP 5: Generate tests

For each component/composable/router/store, create a `.spec.ts` file following the test structure below.
Map every applicable item from the GOES Checklist (see `references/goes-checklist-vue.md`).

Read `references/goes-checklist-vue.md` for the frontend checklist with IDs, epics, features and severities.
Read `references/test-patterns-vue.md` for the exact code patterns to use.

#### Test structure (mandatory for every test)

```typescript
import { describe, it, expect, vi } from 'vitest';
import * as allure from 'allure-js-commons';

// Helper — define ONCE per file
async function attach(name: string, data: unknown) {
  await allure.attachment(name, JSON.stringify(data, null, 2), {
    contentType: 'application/json',
  });
}

it('descriptive test name', async () => {
  // 1. METADATA (all required)
  await allure.epic('...');        // Area: Seguridad | Autenticacion | Configuracion | Dominio
  await allure.feature('...');     // Specific feature
  await allure.story('...');       // Concrete scenario
  await allure.severity('...');    // blocker | critical | normal | minor
  await allure.tag('...');         // Category: XSS, Auth, Config, Pentest
  await allure.tag('...');         // Traceability: OWASP A03, GOES Checklist R5
  await allure.description('...'); // Markdown: ## Objetivo / ## Vulnerabilidad / ## Defensa

  // 2. PARAMETERS (visible inputs)
  await allure.parameter('key', 'value');

  // 3. STEPS (Preparar → Ejecutar → Verificar)
  await allure.step('Preparar: ...', async () => { /* setup */ });
  await attach('Input (input)', data);
  const result = await allure.step('Ejecutar: ...', async () => { return /* action */ });
  await allure.step('Verificar: ...', async () => { expect(result).toBe(...); });
  await attach('Resultado (output)', result);
});
```

#### Rules for PENTEST tests

- Prefix: `'PENTEST: ...'` in the it() name
- Epic: `'Seguridad'`
- Tags: `'Pentest'` + `'OWASP Axx'` + `'GOES Checklist Rxx'`
- Description: must include `## Vulnerabilidad que previene` and `## Defensa implementada`
- Attachments: attacker payload (input) + defense response (output)

### STEP 6: Run tests and generate Allure Report

After generating all test files, you MUST run the tests and generate the report automatically. Do NOT leave this as a manual step for the user.

1. Run the security tests:
   ```bash
   npx vitest run --reporter=default --reporter=allure-vitest
   ```
   If the project has a `test:security` script, use that instead.

2. If any tests fail due to import or config errors, fix them and re-run.

3. Generate the Allure report:
   ```bash
   npx allure generate allure-results --clean -o allure-report
   ```

4. Open the Allure report in the browser:
   ```bash
   npx allure open allure-report
   ```

5. Show summary to the user: total tests, pass/fail count, checklist items covered, OWASP items covered.

**Important:** Steps 1-4 are mandatory and automatic. The user should see the Allure report open in their browser without running any commands manually.

## Important Rules

- NEVER generate empty or placeholder tests — every test must have real assertions against real code
- Read the actual source code BEFORE writing tests
- If a `.spec.ts` or `.test.ts` file already exists, READ IT FIRST. Compare existing tests against the GOES checklist and ONLY add tests that are missing. Never duplicate existing tests.
- Comments in code: NO accents (ASCII only). Allure strings (descriptions, steps): YES accents
- Detect the package manager (pnpm/yarn/npm) and use the correct command
- Each test must be independent — no shared state, no execution order dependency
- Mock API calls with vi.mock() or msw — never make real HTTP requests in tests
- Use @vue/test-utils mount/shallowMount for component testing
