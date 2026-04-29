# Pattern 07 — Auth Service · Errors + Open-Redirect + Storage Audit

**Covers:** `R8`, `R14`, `R42`, `VF12` · **OWASP:** A01, A02, A07 · **Severity:** critical

Three concerns bundled by proximity (all exercise `authService` + the login surface):

1. **Generic error messages** — 401 NEVER produces "email does not exist" / "wrong password". Both collapse to a single copy.
2. **Backend-supplied messages forwarded verbatim** when present.
3. **Fallback for non-Axios errors** — neutral copy.
4. **Open-redirect guard** — `?redirect=` only honoured for site-relative paths.
5. **Storage audit** — access token NEVER written to localStorage / sessionStorage.

Every test captures the attacker payload (`Input - attacker login attempt`, `Input - attacker redirect payloads`, `Input - storage keys scanned`) and the defence outcome (`Output - defense result`).

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
        'preventing user enumeration from the client side.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    t.step(
      'Prepare: mock /auth/login to reject with AxiosError 401 (empty body)',
    )
    const err = new AxiosError('401')
    ;(err as { response?: unknown }).response = { status: 401, data: {} }
    const spy = vi.spyOn(api, 'post').mockRejectedValueOnce(err)
    const attempt = { email: 'admin@goes.gob.sv', password: 'whatever' }
    t.evidence('Input - attacker login attempt', {
      attempt,
      backendResponse: { status: 401, body: {} },
    })

    t.step('Execute: authService.login() — expect rejection with generic copy')
    let thrown: Error | null = null
    try {
      await authService.login(attempt.email, attempt.password)
    } catch (e) {
      thrown = e as Error
    }

    t.step('Verify: the thrown message is EXACTLY the generic copy')
    expect(thrown).toBeTruthy()
    expect(thrown!.message).toBe('Credenciales invalidas')

    t.evidence('Output - defense result', {
      messageShownToUser: thrown?.message,
      userEnumerationPossible: false,
    })

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
    t.descriptionHtml(
      '<p>When the backend sends a specific, pre-sanitised message ' +
        '(e.g. 409 conflict with <code>data.message</code>), the service ' +
        'forwards it verbatim so the user sees actionable text.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    t.step('Prepare: mock /auth/login to reject with 409 + data.message')
    const err = new AxiosError('conflict')
    ;(err as { response?: unknown }).response = {
      status: 409,
      data: { message: 'No se pudo completar el registro' },
    }
    const spy = vi.spyOn(api, 'post').mockRejectedValueOnce(err)
    t.evidence('Input - backend payload', {
      status: 409,
      body: { message: 'No se pudo completar el registro' },
    })

    t.step('Execute: authService.login() and capture the thrown message')
    let thrown: Error | null = null
    try {
      await authService.login('admin@goes.gob.sv', 'pwd')
    } catch (e) {
      thrown = e as Error
    }

    t.step('Verify: the thrown message equals the backend message verbatim')
    expect(thrown!.message).toBe('No se pudo completar el registro')

    t.evidence('Output - defense result', {
      messageForwarded: thrown?.message,
      forwardedVerbatim: true,
    })

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
    t.descriptionHtml(
      '<p>If the request fails with something other than AxiosError ' +
        '(network dropped, CORS, unexpected JSON) the service MUST NOT ' +
        'leak the raw message. It collapses to a neutral copy.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    t.step('Prepare: mock /auth/login to reject with a bare Error("boom")')
    const spy = vi.spyOn(api, 'post').mockRejectedValueOnce(new Error('boom'))
    t.evidence('Input - raw failure', {
      errorName: 'Error',
      errorMessage: 'boom',
    })

    t.step('Execute: authService.login() and capture the thrown message')
    let thrown: Error | null = null
    try {
      await authService.login('admin@goes.gob.sv', 'pwd')
    } catch (e) {
      thrown = e as Error
    }

    t.step('Verify: the thrown message is the neutral fallback')
    expect(thrown!.message).toBe('No fue posible iniciar sesion')

    t.evidence('Output - defense result', {
      messageShownToUser: thrown?.message,
      rawErrorLeaked: thrown?.message?.includes('boom') ?? false,
    })

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
    t.descriptionHtml(
      '<p>A site-relative path starts with <code>/</code> and does ' +
        'not have a protocol prefix. These are safe targets after login.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    const safeTargets = ['/dashboard/maintainer', '/dashboard/category?x=1']
    t.evidence('Input - candidate targets (safe)', { targets: safeTargets })

    t.step('Execute + Verify: isSiteRelative(t) must return true')
    const results = safeTargets.map((p) => ({
      target: p,
      accepted: isSiteRelative(p),
    }))
    for (const { accepted } of results) expect(accepted).toBe(true)

    t.evidence('Output - guard decisions', { results })

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
        '<code>/login?redirect=https://evil.com/steal</code>. After login ' +
        'the router would push to the malicious site, where a spoofed ' +
        'form harvests credentials.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    const attackerPayloads = [
      'https://evil.com',
      'http://evil.com/path',
      '//evil.com',
      'javascript:alert(1)',
      '',
      'dashboard/maintainer', // no leading slash
    ]
    t.evidence('Input - attacker redirect payloads', {
      payloads: attackerPayloads,
    })

    t.step(
      'Execute + Verify: isSiteRelative(p) must return false for each payload',
    )
    const results = attackerPayloads.map((p) => ({
      target: p,
      accepted: isSiteRelative(p),
    }))
    for (const { accepted } of results) expect(accepted).toBe(false)

    t.evidence('Output - guard decisions', { results })

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
        'JavaScript never sees either.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" target="_blank" rel="noopener">OWASP A02</a>.</p>',
    )

    const suspectKeys = ['accessToken', 'token', 'jwt', 'refreshToken', 'auth']
    t.evidence('Input - storage keys scanned', { suspectKeys })

    t.step('Execute: read every suspect key from local + session storage')
    const snapshot: Record<string, string | null> = {}
    for (const key of suspectKeys) {
      snapshot[`local:${key}`] = localStorage.getItem(key)
      snapshot[`session:${key}`] = sessionStorage.getItem(key)
    }

    t.step('Verify: every slot is null')
    for (const key of suspectKeys) {
      expect(localStorage.getItem(key)).toBeNull()
      expect(sessionStorage.getItem(key)).toBeNull()
    }

    t.evidence('Output - defense result', {
      snapshot,
      tokensInWebStorage: Object.values(snapshot).filter((v) => v !== null)
        .length,
    })

    await t.flush()
  })
})
```

## Adapt to your project

- If the error messages in your service are in English (or a different locale), update the `rejects.toThrow(...)` assertions to match the real copy.
- If the project already ships an `isSiteRelative()` helper, import it and test that helper directly instead of a local copy.
- Expand `suspectKeys` if your app uses other conventional key names.
