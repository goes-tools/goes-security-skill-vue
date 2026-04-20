---
name: generate-security-tests-vue
description: >
  This skill should be used when the user asks to "generate security tests for Vue",
  "create frontend security specs", "generate GOES tests for Vue",
  "create XSS tests", "security tests for frontend",
  "tests de seguridad para Vue", "crear tests de seguridad frontend",
  "security report for Vue", "reporte de seguridad frontend",
  or any variation requesting automated security test generation for a Vue.js project.
  Uses a custom HTML reporter (no Java, no Allure) that generates a self-contained
  HTML report with sidebar navigation, charts, and evidence JSON highlighting.
metadata:
  version: "2.0.0"
  coverage: "Checklist GOES (items frontend) + OWASP Top 10 + Custom HTML Report"
---

# GOES Security Test Generator — Vue.js Frontend

Generate professional security tests with a **Custom HTML Reporter** for Vue.js + Vitest projects.
No Java, no Allure — pure Node.js reporter that generates a self-contained HTML file.
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
PKG_CMD add -D vitest @vue/test-utils
```

**DO NOT install Allure, allure-vitest, allure-js-commons, or allure-commandline.** This system uses a custom pure Node.js reporter that generates HTML directly — no Java required.

### STEP 3: Set up the custom reporter

The reporter system lives in `test/security/reporter/` and consists of two files:

```
test/security/
├── reporter/
│   ├── html-reporter.js    ← Vitest custom reporter (JavaScript, ~1600 lines)
│   └── metadata.ts         ← Metadata collector per test
├── *.security.spec.ts      ← Security test spec files
└── vitest.security.config.ts ← Vitest config for security tests
```

#### reporter/metadata.ts

Exports `report()` function and `AllureCompat` class. Each test uses these to register metadata (epic, feature, story, severity, tags, steps, evidence). Metadata is written to temp JSON files that the reporter reads when tests finish.

```typescript
import { report } from './reporter/metadata';

it('test name', async () => {
  const t = report();
  t.epic('Security');
  t.feature('XSS Prevention');
  t.story('Block script injection via v-html');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A03');
  t.parameter('payload', '<script>alert("xss")</script>');
  t.step('Prepare malicious payload');
  // ... test logic ...
  t.evidence('Result', { blocked: true });
  await t.flush();
});
```

#### reporter/html-reporter.js

Custom Vitest reporter (plain JavaScript — Vitest loads reporters with `require()`, not through ts transforms). Implements `onFinished(files, errors)`:
1. Reads `meta-*.json` files from temp directory
2. Matches metadata with test results by `testPath::testName` key
3. Generates self-contained HTML with CSS, JS, and embedded data
4. Features: sidebar Epic>Feature>Story navigation, detail modal with severity badges, SVG charts, dark theme, search, PDF export
5. Cleans up temp files

#### vitest.security.config.ts

```typescript
import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';
import path from 'path';

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '../..', 'src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    include: ['test/security/**/*.security.spec.ts'],
    reporters: [
      'default',
      ['./test/security/reporter/html-reporter.js', {
        outputPath: './reports/security/security-report.html',
      }],
    ],
  },
});
```

Add scripts to `package.json`:

```json
{
  "test:security": "vitest run --config test/security/vitest.security.config.ts",
  "test:security:watch": "vitest --config test/security/vitest.security.config.ts"
}
```

Add to `.gitignore`:

```
/reports
```

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

For each component/composable/router/store, create a `.security.spec.ts` file following the test structure below.
Map every applicable item from the GOES Checklist (see `references/goes-checklist-vue.md`).

Read `references/goes-checklist-vue.md` for the frontend checklist with IDs, epics, features and severities.
Read `references/test-patterns-vue.md` for the exact code patterns to use.

#### Test structure (mandatory for every test)

```typescript
import { describe, it, expect, vi } from 'vitest';
import { report } from './reporter/metadata';

it('descriptive test name', async () => {
  const t = report();

  // 1. METADATA (all required)
  t.epic('Security');           // Area: Security | Authentication | Configuration | Domain
  t.feature('XSS Prevention');  // Specific feature
  t.story('Block injection');   // Concrete scenario
  t.severity('blocker');        // blocker | critical | normal | minor
  t.tag('Pentest', 'OWASP A03', 'GOES Checklist R5');

  // 2. PARAMETERS (visible inputs)
  t.parameter('payload', '<script>alert(1)</script>');

  // 3. STEPS (Prepare → Execute → Verify)
  t.step('Prepare: create malicious payload');
  t.evidence('Input (payload)', { payload: '<script>alert(1)</script>' });

  t.step('Execute: render component with payload');
  const wrapper = mount(MyComponent, { props: { content: payload } });

  t.step('Verify: script tag is sanitized');
  expect(wrapper.html()).not.toContain('<script>');
  t.evidence('Result (output)', { sanitized: true, html: wrapper.html() });

  await t.flush();
});
```

#### Rules for PENTEST tests

- Prefix: `'PENTEST: ...'` in the it() name
- Epic: `'Security'`
- Tags: `'Pentest'` + `'OWASP Axx'` + `'GOES Checklist Rxx'`
- Evidence: attacker payload (input) + defense response (output)

#### Critical rule: flush()

Every test MUST call `await t.flush()` at the end. Without flush, metadata is not written and the report will not have the test's details.

### STEP 6: Run tests and generate report

After generating all test files, run the tests automatically:

1. Run the security tests:
   ```bash
   npm run test:security
   ```

2. If any tests fail due to import or config errors, fix them and re-run.

3. The HTML report is automatically generated at `reports/security/security-report.html` — no extra commands needed.

4. Show summary to the user: total tests, pass/fail count, checklist items covered, OWASP items covered.

**Important:** The report is generated automatically by the custom reporter. No `allure generate` or `allure open` commands are needed. The user just opens the HTML file in their browser.

## Important Rules

- NEVER generate empty or placeholder tests — every test must have real assertions against real code
- Read the actual source code BEFORE writing tests
- If a `.spec.ts` or `.test.ts` file already exists, READ IT FIRST. Compare existing tests against the GOES checklist and ONLY add tests that are missing. Never duplicate existing tests.
- Comments in code: NO accents (ASCII only). Metadata strings (steps, stories): YES accents
- Detect the package manager (pnpm/yarn/npm) and use the correct command
- Each test must be independent — no shared state, no execution order dependency
- Mock API calls with vi.mock() or msw — never make real HTTP requests in tests
- Use @vue/test-utils mount/shallowMount for component testing
- Every test MUST end with `await t.flush()` — without this the metadata doesn't reach the report
- The reporter html-reporter.js MUST be plain JavaScript — Vitest loads reporters with require()
- Spec files must end in `.security.spec.ts` — this is the pattern the vitest config matches
- DO NOT install Allure, allure-commandline, or Java — this system is pure Node.js
