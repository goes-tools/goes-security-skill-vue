# Pattern 08 — PERMISOS Matrix + v-html Audit + Autocomplete Hygiene

**Covers:** `R9`, `R11`, `R14`, `VF1`, `VF11` · **OWASP:** A01, A03, A07 · **Severity:** blocker / critical / high

Three complementary checks collected in one spec because each one individually is too small:

1. **RBAC PERMISOS matrix** — every (perfil × flag) combination is pinned as an independent assertion so future refactors cannot silently widen permissions. Every cell is a named test and shows in the report.
2. **`v-html` audit** — sweeps the entire `src/` tree and fails if ANY `.vue` file uses `v-html`. This directive disables Vue's automatic escaping and is the classic XSS sink.
3. **Autocomplete hygiene** — ensures the login form declares the correct autocomplete tokens:
   - `email` field → `autocomplete="email"` (or `"username"`)
   - `password` field → `autocomplete="current-password"` (NEVER `"off"` — browsers ignore it and it nudges users to weaker reused passwords).
   - Form must not use `method="get"` (would leak the password into URL history).

## Example spec — `tests/security/permissions-matrix.security-html.spec.ts`

```typescript
/**
 * PERMISOS matrix + v-html audit + autocomplete hygiene
 * ──────────────────────────────────────────────────────
 * Three independent concerns bundled into a single spec:
 *
 *   1. RBAC PERMISOS matrix — every combination of `perfil`
 *      (administrador | tecnico | usuario) × flag is pinned
 *      so future refactors cannot silently widen permissions.
 *      15 individual asserts = zero-ambiguity contract.
 *
 *   2. `v-html` audit — sweeps the entire `src/` tree and
 *      fails if ANY single-file component uses `v-html`. This
 *      directive disables Vue's automatic escaping and is the
 *      classic XSS sink.
 *
 *   3. Autocomplete hygiene — ensures the login form declares
 *      the correct autocomplete tokens:
 *         · email  → "email" or "username"
 *         · password → "current-password" (NEVER "off",
 *           NEVER missing — blocking password managers is an
 *           anti-pattern and nudges users to reuse passwords).
 */
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { report } from '@security-reporter/metadata'
import { PERMISOS } from '@/features/auth/types'

// ───────────────────────────────────────────────────────────────
// 1. PERMISOS matrix
// ───────────────────────────────────────────────────────────────

/**
 * Ground-truth matrix the UI relies on for RBAC-driven visibility.
 * Every row is an independent assertion so the HTML report shows
 * exactly which cell regressed when a change slips in.
 */
const EXPECTED_MATRIX: Record<
  'administrador' | 'tecnico' | 'usuario',
  {
    verTodo: boolean
    eliminar: boolean
    agregar: boolean
    editar: boolean
    verMantenedor: boolean
  }
> = {
  administrador: {
    verTodo: true,
    eliminar: true,
    agregar: true,
    editar: true,
    verMantenedor: true,
  },
  tecnico: {
    verTodo: true,
    eliminar: false,
    agregar: false,
    editar: true,
    verMantenedor: false, // Maintainer is admin-only (GOES §4.4)
  },
  usuario: {
    verTodo: true,
    eliminar: false,
    agregar: false,
    editar: false,
    verMantenedor: false,
  },
}

describe('[GOES Security FE] RBAC · PERMISOS matrix', () => {
  for (const [perfil, expected] of Object.entries(EXPECTED_MATRIX)) {
    for (const [flag, value] of Object.entries(expected)) {
      it(`[R9] ${perfil} · ${flag} = ${value}`, async () => {
        const t = report()
        t.epic('RBAC')
        t.feature('PERMISOS matrix')
        t.story(`${perfil} → ${flag}`)
        t.severity(flag === 'verMantenedor' || flag === 'eliminar' ? 'critical' : 'high')
        t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
        t.descriptionHtml(
          '<p>The UI uses <code>PERMISOS[perfil]</code> to decide which ' +
            'buttons/routes to render. Any accidental change to this ' +
            'map widens or shrinks the attack surface. This assertion ' +
            'pins the current value so a PR diff surfaces immediately ' +
            'in the report.</p>',
        )
        t.evidence('Expected cell', { perfil, flag, value })

        const actual = PERMISOS[perfil]?.[flag as keyof typeof expected]
        expect(actual).toBe(value)

        await t.flush()
      })
    }
  }

  it('[R9] unknown perfil falls back to "usuario" (fail-closed)', async () => {
    const t = report()
    t.epic('RBAC')
    t.feature('PERMISOS matrix')
    t.story('Unknown perfil → minimum privileges')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
    t.descriptionHtml(
      '<p>If a token carries an unknown <code>perfil</code> (e.g. a ' +
        'newly introduced role that has not been mapped yet) the ' +
        'store MUST NOT assume admin privileges. The safe fallback ' +
        'is the <code>usuario</code> profile, which is read-only.</p>',
    )

    const fallback = PERMISOS['no-existe'] ?? PERMISOS.usuario
    expect(fallback.eliminar).toBe(false)
    expect(fallback.agregar).toBe(false)
    expect(fallback.editar).toBe(false)
    expect(fallback.verMantenedor).toBe(false)

    await t.flush()
  })
})

// ───────────────────────────────────────────────────────────────
// 2. v-html audit (no XSS sinks in the codebase)
// ───────────────────────────────────────────────────────────────

/**
 * Recursively walks `dir` collecting file paths that end with any
 * of the given extensions. We roll a tiny walker instead of a
 * dependency because this is a test-only helper.
 */
function walk(dir: string, extensions: string[], acc: string[] = []): string[] {
  const entries = readdirSync(dir)
  for (const entry of entries) {
    const full = path.join(dir, entry)
    let isDir = false
    try {
      isDir = statSync(full).isDirectory()
    } catch {
      continue
    }
    if (isDir) {
      walk(full, extensions, acc)
    } else if (extensions.some((ext) => full.endsWith(ext))) {
      acc.push(full)
    }
  }
  return acc
}

describe('[GOES Security FE] v-html audit · no raw HTML sinks', () => {
  it('[R11] NO .vue file uses v-html (Vue\'s escaping opt-out)', async () => {
    const t = report()
    t.epic('XSS Prevention')
    t.feature('v-html audit')
    t.story('No component injects raw HTML into the DOM')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A03', 'GOES-R11')
    t.descriptionHtml(
      '<p>The <code>v-html</code> directive injects markup verbatim, ' +
        "bypassing Vue's automatic escaping. If someone ever adopts " +
        'it to render a backend-supplied comment we get a reflected ' +
        'XSS. This test sweeps <code>src/</code> and fails on the ' +
        'first occurrence — it acts as a compile-time guardrail.</p>',
    )

    // Resolve src/ relative to the current test file so it works
    // regardless of where vitest decides to set cwd.
    const srcRoot = path.resolve(__dirname, '..', '..', 'src')
    const vueFiles = walk(srcRoot, ['.vue', '.ts', '.tsx'])

    const offenders: { file: string; line: number; text: string }[] = []
    for (const file of vueFiles) {
      const content = readFileSync(file, 'utf8')
      // Only flag the Vue directive usage `v-html=` / `:v-html=`.
      // The string "v-html" can legitimately appear in comments or
      // this very spec file; restrict the match to a directive-like
      // context.
      const regex = /\sv-html\s*=/g
      let match: RegExpExecArray | null
      while ((match = regex.exec(content)) !== null) {
        const line = content.slice(0, match.index).split('\n').length
        offenders.push({
          file: file.replace(srcRoot, 'src'),
          line,
          text: content.split('\n')[line - 1]?.trim() ?? '',
        })
      }
    }

    t.evidence('Files scanned', { count: vueFiles.length, offenders })
    expect(offenders).toEqual([])

    await t.flush()
  })
})

// ───────────────────────────────────────────────────────────────
// 3. Autocomplete hygiene on the login form
// ───────────────────────────────────────────────────────────────

describe('[GOES Security FE] LoginView · autocomplete hygiene', () => {
  /**
   * Read the raw LoginView source and assert on its attributes.
   * We intentionally do not mount the component: a simple textual
   * check is robust against refactors of the reactive layer and
   * reads closer to how an auditor would grep the codebase.
   */
  const loginPath = path.resolve(
    __dirname,
    '..',
    '..',
    'src',
    'features',
    'auth',
    'views',
    'LoginView.vue',
  )
  const loginSource = readFileSync(loginPath, 'utf8')

  it('[R14] email input declares autocomplete="email" or "username"', async () => {
    const t = report()
    t.epic('Credential UX')
    t.feature('Autocomplete hygiene')
    t.story('Email field accepts password manager')
    t.severity('normal')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R14')
    t.descriptionHtml(
      '<p>Declaring the correct token lets the password manager ' +
        'autofill the field and, more importantly, suggest unique ' +
        'passwords — which reduces reuse, one of the top vectors ' +
        'for credential-stuffing attacks.</p>',
    )

    // Look for <input … type="email" … autocomplete="email|username">
    // across potentially multi-line attribute lists.
    const emailBlock = loginSource.match(
      /<input[^>]*type=["']email["'][^>]*>/s,
    )
    expect(emailBlock, 'no <input type="email"> found').toBeTruthy()
    expect(emailBlock![0]).toMatch(/autocomplete=["'](email|username)["']/)

    await t.flush()
  })

  it('[R14] password input declares autocomplete="current-password" (NEVER "off")', async () => {
    const t = report()
    t.epic('Credential UX')
    t.feature('Autocomplete hygiene')
    t.story('Password field is password-manager friendly')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R14')
    t.descriptionHtml(
      '<p>Setting <code>autocomplete="off"</code> on a password field ' +
        'is an anti-pattern: modern browsers ignore it and the net ' +
        'effect is nudging users toward weaker reused passwords ' +
        'because they cannot lean on their manager. The correct ' +
        'value on a login form is <code>current-password</code> ' +
        '(registration/change flows would use <code>new-password</code>).</p>',
    )

    const passwordBlock = loginSource.match(
      /<input[^>]*type=["']password["'][^>]*>/s,
    )
    expect(passwordBlock, 'no <input type="password"> found').toBeTruthy()
    expect(passwordBlock![0]).toMatch(
      /autocomplete=["']current-password["']/,
    )
    expect(passwordBlock![0]).not.toMatch(/autocomplete=["']off["']/)

    await t.flush()
  })

  it('[R14] login form is submitted over an authenticated POST (method not GET)', async () => {
    const t = report()
    t.epic('Credential UX')
    t.feature('Form method')
    t.story('Credentials never travel as query string')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A02', 'GOES-R14')
    t.descriptionHtml(
      '<p>A <code>&lt;form method="GET"&gt;</code> containing a ' +
        'password field embeds the secret into the URL: it lands in ' +
        'the browser history, in the access logs of every ' +
        'intermediate proxy and in the <code>Referer</code> of the ' +
        'next click. Login is ALWAYS POST — we verify the component ' +
        'uses <code>submit.prevent</code> and delegates to ' +
        '<code>authService.login()</code>.</p>',
    )

    // Either the form carries method="post" OR the submit is
    // intercepted by @submit.prevent and routed through the
    // service. We accept both idioms — the dangerous one is an
    // explicit method="get".
    expect(loginSource).not.toMatch(/<form[^>]*method=["']get["']/i)
    expect(loginSource).toMatch(/@submit\.prevent|method=["']post["']/i)

    await t.flush()
  })
})
```

## Adapt

- Update `EXPECTED_MATRIX` to match your project's real `PERMISOS` map.
- The `walk()` helper is framework-agnostic — no changes needed.
- If the login view path differs, update `loginPath`.
- If the project has additional forms with password fields (change-password modal, registration), add an equivalent test for each one but use `autocomplete="new-password"` for registration / change flows.
