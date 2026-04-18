# goes-security-skill-vue

Claude skill for generating automated security tests with **Allure Report** for **Vue.js + Vitest** projects.

Covers the **GOES Cybersecurity Checklist** (frontend items), **OWASP Top 10**, and common frontend security vulnerabilities.

---

## Installation

### 1. Clone this repo

```bash
git clone https://github.com/goes-tools/goes-security-skill-vue.git
```

### 2. Copy the `.claude/` folder to your Vue.js project

```bash
cp -r goes-security-skill-vue/.claude/ /path/to/your-vue-project/.claude/
```

Your project structure will look like:

```
your-vue-project/
  .claude/
    skills/
      goes-security-vue/
        SKILL.md                          <-- instructions for Claude
        references/
          goes-checklist-vue.md           <-- GOES checklist (frontend items)
          test-patterns-vue.md            <-- 8 code patterns
  src/
  package.json
  ...
```

### 3. Open Claude in your project

Open **Claude Code** or **Claude Cowork** in your project folder.

### 4. Ask Claude to generate the tests

```
Generate security tests for the auth store and router guards.
Use the goes-security-vue skill, cover all applicable GOES checklist items,
and generate pentest tests with Allure Report and OWASP traceability.
```

Claude reads the skill, analyzes your actual code, installs dependencies, and generates the tests automatically.

---

## What Claude does

When you activate the skill, Claude:

1. Analyzes your components, stores, router, and composables
2. Installs dependencies if missing (`allure-vitest`, `allure-js-commons`, `allure-commandline`)
3. Configures Vitest to generate Allure reports
4. Generates `.spec.ts` files with:
   - Allure metadata (epic, feature, story, severity, tags)
   - Triple traceability: `GOES Checklist Rxx` + `OWASP Axx`
   - Visible steps (Prepare / Execute / Verify)
   - JSON attachments (attacker payload + defense response)
   - Markdown descriptions (vulnerability + defense)

---

## Usage examples

```
> Generate security tests for the auth store
> Generate security tests for the router guards
> Generate security tests for all components that use v-html
> Generate security tests for the API interceptor
> Generate all frontend security tests
```

### View the interactive report

```bash
npm test
npx allure generate allure-results --clean -o allure-report
npx allure open allure-report
```

---

## Coverage

### GOES Cybersecurity Checklist (Frontend)

| Category | Items | Covers |
|----------|-------|--------|
| Web Content | R3-R6 | Sensitive data, XSS, sanitization |
| Input/Output | R8, R10-R11 | Generic errors, console.log, validation |
| Auth & Sessions | R13-R35 | Route guards, RBAC, token storage, session timeout |
| Configuration | R42-R50 | Cookies, CSP, debug mode, cache control |
| Vue-Specific | VF1-VF10 | v-html XSS, interceptors, env vars, store cleanup |

### OWASP Top 10

A01 (Broken Access Control), A02 (Crypto Failures), A03 (Injection), A05 (Security Misconfiguration), A07 (Auth Failures), A09 (Logging Failures)

### Test Patterns Included

1. XSS via v-html
2. Route Guard — Authentication
3. Route Guard — Role-Based Access
4. Token Storage Security
5. API Interceptor — 401 Handling
6. Environment Variable Security
7. Store Cleanup on Logout
8. Console.log in Production

---

## Package Manager Support

The skill automatically detects your package manager:

- `pnpm-lock.yaml` → uses `pnpm add -D`
- `yarn.lock` → uses `yarn add -D`
- `package-lock.json` → uses `npm install --save-dev`

---

## Requirements

- **Vue.js 3** project with Vitest (or Jest)
- **Node.js 18+**
- **No Java required** — uses the pure JavaScript `allure` package (v3+)

---

## Contributing

PRs are welcome for:

- Adding new test patterns in `references/test-patterns-vue.md`
- Updating the checklist in `references/goes-checklist-vue.md`
- Improving skill instructions in `SKILL.md`
- Adding support for Nuxt.js

### How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b feature/new-pattern`
3. Make changes
4. PR with description of what was added/changed

---

## License

Internal use — Government of El Salvador (GOES)
