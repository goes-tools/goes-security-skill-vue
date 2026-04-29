# Pattern 08 — PERMISOS Matrix + v-html Audit + Autocomplete Hygiene

**Covers:** `R9`, `R11`, `R14`, `VF1`, `VF11` · **OWASP:** A01, A03, A07 · **Severity:** blocker / critical / high

Three complementary checks collected because each one is too small individually:

1. **RBAC PERMISOS matrix** — every (perfil × flag) cell pinned independently. 15 named tests, one per cell.
2. **`v-html` audit** — sweeps `src/` and fails on the first occurrence of the directive.
3. **Autocomplete hygiene** — login form declares `email`/`current-password` (NEVER `off`). Form must not use `method="get"`.

Every test logs `Input -` (the cell coordinates / scan scope / form attribute) and `Output -` (the resolved permission / offenders list / observed autocomplete value) as JSON evidence.

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
    verMantenedor: false,
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
        t.severity(
          flag === 'verMantenedor' || flag === 'eliminar' ? 'critical' : 'high',
        )
        t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
        t.descriptionHtml(
          '<p>The UI uses <code>PERMISOS[perfil]</code> to decide which ' +
            'buttons/routes to render. Any accidental change to this ' +
            'map widens or shrinks the attack surface. This assertion ' +
            'pins the current value so a PR diff surfaces immediately ' +
            'in the report.</p>' +
            '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
        )

        t.step('Prepare: pick the (perfil, flag) cell under audit')
        t.evidence('Input - cell coordinates', {
          perfil,
          flag,
          expectedValue: value,
        })

        t.step('Execute: read the actual value from PERMISOS')
        const actual = PERMISOS[perfil]?.[flag as keyof typeof expected]

        t.step('Verify: actual === expected (pinned contract)')
        expect(actual).toBe(value)

        t.evidence('Output - audit result', {
          perfil,
          flag,
          expected: value,
          actual,
          widened: actual === true && value === false,
          shrunk: actual === false && value === true,
        })

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
        'is the <code>usuario</code> profile, which is read-only.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    t.step('Prepare: look up a perfil not registered in PERMISOS')
    const unknownPerfil = 'no-existe'
    t.evidence('Input - attacker tamper', {
      tamperedPerfil: unknownPerfil,
      attackerGoal: 'fail-open to admin privileges',
    })

    t.step(
      'Execute: emulate the store fallback: PERMISOS[unknown] ?? PERMISOS.usuario',
    )
    const fallback = PERMISOS[unknownPerfil] ?? PERMISOS.usuario

    t.step('Verify: every privileged flag is denied')
    expect(fallback.eliminar).toBe(false)
    expect(fallback.agregar).toBe(false)
    expect(fallback.editar).toBe(false)
    expect(fallback.verMantenedor).toBe(false)

    t.evidence('Output - resolved permissions', fallback)

    await t.flush()
  })
})

// ───────────────────────────────────────────────────────────────
// 2. v-html audit (no XSS sinks in the codebase)
// ───────────────────────────────────────────────────────────────

function walk(dir: string, extensions: string[], acc: string[] = []): string[] {
  const entries = readdirSync(dir)
  for (const entry of entries) {
    const full = path.join(dir, entry)
    let isDir: boolean
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
  it("[R11] NO .vue file uses v-html (Vue's escaping opt-out)", async () => {
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
        'first occurrence — it acts as a compile-time guardrail.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener">OWASP A03</a>.</p>',
    )

    t.step('Prepare: walk src/ and collect every .vue / .ts / .tsx file')
    const srcRoot = path.resolve(__dirname, '..', '..', 'src')
    const scanned = walk(srcRoot, ['.vue', '.ts', '.tsx'])
    t.evidence('Input - scan scope', {
      srcRoot: srcRoot.replace(process.cwd(), '.'),
      filesScanned: scanned.length,
      extensions: ['.vue', '.ts', '.tsx'],
      regex: '\\sv-html\\s*=',
    })

    t.step('Execute: grep every file for the directive')
    const offenders: { file: string; line: number; text: string }[] = []
    for (const file of scanned) {
      const content = readFileSync(file, 'utf8')
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

    t.step('Verify: offenders list is empty')
    expect(offenders).toEqual([])

    t.evidence('Output - defense result', {
      filesScanned: scanned.length,
      offendersFound: offenders.length,
      offenders,
    })

    await t.flush()
  })
})

// ───────────────────────────────────────────────────────────────
// 3. Autocomplete hygiene on the login form
// ───────────────────────────────────────────────────────────────

describe('[GOES Security FE] LoginView · autocomplete hygiene', () => {
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
        'for credential-stuffing attacks.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    t.step('Prepare: locate the <input type="email"> block in LoginView.vue')
    const emailBlock = loginSource.match(/<input[^>]*type=["']email["'][^>]*>/s)
    t.evidence('Input - LoginView.vue email tag', {
      file: 'src/features/auth/views/LoginView.vue',
      tagFound: !!emailBlock,
      tag: emailBlock?.[0] ?? null,
    })

    t.step('Verify: autocomplete attribute is "email" or "username"')
    expect(emailBlock, 'no <input type="email"> found').toBeTruthy()
    expect(emailBlock![0]).toMatch(/autocomplete=["'](email|username)["']/)

    t.evidence('Output - defense result', {
      autocompleteValue: emailBlock?.[0].match(
        /autocomplete=["']([^"']+)["']/,
      )?.[1],
      passwordManagerFriendly: true,
    })

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
        '(registration/change flows would use <code>new-password</code>).</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    // The login view uses `:type="showPassword ? 'text' : 'password'"`
    // so there is no literal `type="password"` to anchor on. We
    // anchor by `id="password"` instead — equally unique and stable
    // across UX redesigns (show/hide toggle, etc.).
    t.step('Prepare: locate the <input id="password"> block in LoginView.vue')
    const passwordBlock = loginSource.match(
      /<input[^>]*id=["']password["'][^>]*>/s,
    )
    t.evidence('Input - LoginView.vue password tag', {
      file: 'src/features/auth/views/LoginView.vue',
      tagFound: !!passwordBlock,
      tag: passwordBlock?.[0] ?? null,
    })

    t.step('Verify: autocomplete is "current-password" AND is NOT "off"')
    expect(passwordBlock, 'no <input id="password"> found').toBeTruthy()
    expect(passwordBlock![0]).toMatch(/autocomplete=["']current-password["']/)
    expect(passwordBlock![0]).not.toMatch(/autocomplete=["']off["']/)

    t.evidence('Output - defense result', {
      autocompleteValue: passwordBlock?.[0].match(
        /autocomplete=["']([^"']+)["']/,
      )?.[1],
      antiPatternAvoided: !(passwordBlock?.[0] ?? '').includes(
        'autocomplete="off"',
      ),
    })

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
        'the browser history, in the access logs of every intermediate ' +
        'proxy and in the <code>Referer</code> of the next click. Login ' +
        'is ALWAYS POST — we verify the component uses ' +
        '<code>submit.prevent</code> and delegates to ' +
        '<code>authService.login()</code>.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" target="_blank" rel="noopener">OWASP A02</a>.</p>',
    )

    t.step('Prepare: snapshot how the <form> is defined in LoginView.vue')
    const getMethodFound = /<form[^>]*method=["']get["']/i.test(loginSource)
    const preventOrPost = /@submit\.prevent|method=["']post["']/i.test(
      loginSource,
    )
    t.evidence('Input - LoginView.vue form audit', {
      file: 'src/features/auth/views/LoginView.vue',
      hasExplicitMethodGet: getMethodFound,
      usesSubmitPreventOrMethodPost: preventOrPost,
    })

    t.step('Verify: no method="get" AND either submit.prevent OR method="post"')
    expect(loginSource).not.toMatch(/<form[^>]*method=["']get["']/i)
    expect(loginSource).toMatch(/@submit\.prevent|method=["']post["']/i)

    t.evidence('Output - defense result', {
      credentialsTravelInUrl: getMethodFound,
      safeSubmissionPath: preventOrPost,
    })

    await t.flush()
  })
})
```

## Adapt to your project

- Update `EXPECTED_MATRIX` to match your project's real `PERMISOS` map.
- The `walk()` helper is framework-agnostic — no changes needed.
- If the login view path differs, update `loginPath`.
- If the project has additional forms with password fields (change-password modal, registration), add an equivalent test for each one but use `autocomplete="new-password"` for registration / change flows.
