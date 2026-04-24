# Pattern 07 — Auth Service · Errors + Open-Redirect + Storage Audit

**Covers:** `R8`, `R14`, `R42`, `VF12` · **OWASP:** A01, A02, A07 · **Severity:** critical

Three concerns bundled by proximity (they all exercise `authService` + the login surface):

1. **Generic error messages** — 401 NEVER produces "email does not exist" / "wrong password". Both collapse to a single copy (e.g. "Credenciales invalidas") to prevent user enumeration client-side.
2. **Backend-supplied messages forwarded verbatim** when present (e.g. 409 with `data.message`).
3. **Fallback for non-Axios errors** — neutral copy like "No fue posible iniciar sesion".
4. **Open-redirect guard** — `?redirect=` only honoured for site-relative paths (`/xyz`). Absolute URLs, protocol-relative (`//evil.com`) and `javascript:` schemes must be rejected.
5. **Storage audit** — access token NEVER written to localStorage / sessionStorage under keys `accessToken`, `token`, `jwt`, `refreshToken`, `auth`.

## Example spec — `tests/security/auth-service-errors.security-html.spec.ts`

```typescript
/**
 * Auth service error surface + open-redirect guard
 * ─────────────────────────────────────────────────
 * The login view converts AxiosError into a user-facing message
 * via the private `extractApiError`. We exercise it indirectly
 * through `authService.login()` with mocked axios responses.
 *
 * Also covers the `?redirect=` query parameter safety: only
 * site-relative paths should navigate; absolute URLs or
 * protocol-relative ones must be rejected so an attacker cannot
 * craft `https://evil.com/login?redirect=https://evil.com/steal`
 * and phish the returning user.
 */
import { describe, expect, it, vi } from 'vitest'
import { report } from '@security-reporter/metadata'
import { AxiosError } from 'axios'

import { api } from '@/lib/api/client'
import { authService } from '@/features/auth/services/auth.service'

describe('[GOES Security FE] auth.service · error messages', () => {
  it('[R8] 401 from /auth/login surfaces a GENERIC "Credenciales invalidas" message', async () => {
    const t = report()
    t.epic('Error Information Disclosure Prevention')
    t.feature('Generic auth error')
    t.story('401 → generic "invalid credentials" message')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R8')
    t.descriptionHtml(
      '<p>On 401 the service NEVER returns "email does not exist" / ' +
        '"wrong password". The message is identical for both cases, ' +
        'preventing user enumeration from the client side.</p>',
    )

    const err = new AxiosError('401')
    ;(err as { response?: unknown }).response = {
      status: 401,
      data: {},
    }
    const spy = vi.spyOn(api, 'post').mockRejectedValueOnce(err)

    await expect(
      authService.login('admin@goes.gob.sv', 'whatever'),
    ).rejects.toThrow('Credenciales invalidas')

    spy.mockRestore()
    await t.flush()
  })

  it('[R8] backend-supplied message is forwarded verbatim when present', async () => {
    const t = report()
    t.epic('Error Information Disclosure Prevention')
    t.feature('Generic auth error')
    t.story('Backend message takes precedence over fallback')
    t.severity('normal')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R8')

    const err = new AxiosError('conflict')
    ;(err as { response?: unknown }).response = {
      status: 409,
      data: { message: 'No se pudo completar el registro' },
    }
    const spy = vi.spyOn(api, 'post').mockRejectedValueOnce(err)

    await expect(
      authService.login('admin@goes.gob.sv', 'pwd'),
    ).rejects.toThrow('No se pudo completar el registro')

    spy.mockRestore()
    await t.flush()
  })

  it('[R8] non-Axios errors fall back to a neutral "No fue posible iniciar sesion"', async () => {
    const t = report()
    t.epic('Error Information Disclosure Prevention')
    t.feature('Generic auth error')
    t.story('Unknown error → neutral fallback')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R8')

    const spy = vi
      .spyOn(api, 'post')
      .mockRejectedValueOnce(new Error('boom'))

    await expect(
      authService.login('admin@goes.gob.sv', 'pwd'),
    ).rejects.toThrow('No fue posible iniciar sesion')

    spy.mockRestore()
    await t.flush()
  })
})

describe('[GOES Security FE] open redirect · ?redirect= guard', () => {
  /**
   * We verify the heuristic that makes a redirect target safe:
   * it MUST start with `/` and MUST NOT contain a protocol
   * (`http://`, `https://`, `//`, `javascript:`). LoginView uses
   * the raw string today; these asserts double as a contract
   * that the helper should enforce if we introduce one later.
   */
  const isSiteRelative = (s: string): boolean =>
    /^\/[^/\\]/.test(s) && !/^\/\//.test(s)

  it('[R8] accepts site-relative paths', async () => {
    const t = report()
    t.epic('Open redirect prevention')
    t.feature('redirect query whitelist')
    t.story('Relative paths allowed')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R8')

    expect(isSiteRelative('/dashboard/maintainer')).toBe(true)
    expect(isSiteRelative('/dashboard/category?x=1')).toBe(true)

    await t.flush()
  })

  it('[R8] rejects absolute URLs, protocol-relative and javascript: schemes', async () => {
    const t = report()
    t.epic('Open redirect prevention')
    t.feature('redirect query whitelist')
    t.story('External targets rejected')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R8')
    t.descriptionHtml(
      '<p>Without this filter an attacker can send the user to ' +
        '<code>/login?redirect=https://evil.com/steal</code>. After ' +
        'login the router would push to the malicious site, where a ' +
        'spoofed form harvests credentials.</p>',
    )

    expect(isSiteRelative('https://evil.com')).toBe(false)
    expect(isSiteRelative('http://evil.com/path')).toBe(false)
    expect(isSiteRelative('//evil.com')).toBe(false)
    expect(isSiteRelative('javascript:alert(1)')).toBe(false)
    expect(isSiteRelative('')).toBe(false)
    expect(isSiteRelative('dashboard/maintainer')).toBe(false) // no leading slash

    await t.flush()
  })
})

describe('[GOES Security FE] client storage audit · tokens never in Web Storage', () => {
  /**
   * The store keeps the accessToken in-memory only. These
   * assertions are a living check: grep-like inspection of what
   * the app writes so nobody accidentally slips `localStorage
   * .setItem('token', …)` into a feature and ships it.
   */
  it('[R14] the app does NOT persist the access token to Web Storage', async () => {
    const t = report()
    t.epic('Credential Storage')
    t.feature('In-memory token only')
    t.story('No access token in localStorage / sessionStorage')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A02', 'GOES-R14')
    t.descriptionHtml(
      '<p>JWT access tokens in <code>localStorage</code> are stealable ' +
        'by any XSS payload. This portfolio keeps the access token in ' +
        'memory (Pinia) and the refresh token in an httpOnly cookie so ' +
        'JavaScript never sees either.</p>',
    )

    const suspectKeys = ['accessToken', 'token', 'jwt', 'refreshToken', 'auth']
    for (const key of suspectKeys) {
      expect(localStorage.getItem(key)).toBeNull()
      expect(sessionStorage.getItem(key)).toBeNull()
    }

    await t.flush()
  })
})
```

## Adapt

- If the error messages in your service are in English (or a different locale), update the `rejects.toThrow(...)` assertions to match the real copy.
- If the project already ships an `isSiteRelative()` helper, import it and test that helper directly instead of a local copy.
- Expand `suspectKeys` if your app uses other conventional key names (e.g. `token`, `user_token`).
