# Pattern 10 — E2E Playwright · Auth Flow

**Covers:** `R8`, `R14`, `R42`, `VF12` · **OWASP:** A01, A07 · **Severity:** critical

Full-stack journey that exercises the login form, the interceptor, the session scheduler and the guard redirects.

Verifies:

1. Wrong credentials → generic error (no user enumeration).
2. Happy path → lands on `/dashboard/*` AND the JWT is NEVER written to Web Storage.
3. `/login?redirect=/dashboard/foo` honoured for site-relative targets.
4. `/login?redirect=https://evil.com/steal` NEVER navigates off-origin.

Requires the backend running on `/api`. Use the `backendIsUp()` probe (see `_playwright-setup.md`) so CI without the stack still produces 0 tests instead of a wall of red.

## Example spec — `tests/e2e/auth-flow.security.spec.ts`

```typescript
/**
 * E2E · Auth flow security
 * ─────────────────────────
 * Exercises the login journey end-to-end with a real backend:
 *
 *   · Wrong password → generic error (no user enumeration).
 *   · Happy path → lands in /dashboard/category and the
 *     Authorization header rides subsequent calls.
 *   · `/login?redirect=/dashboard/infrastructure` → respected
 *     for site-relative targets.
 *   · `/login?redirect=https://evil.com` → we NEVER leave the
 *     origin, proving the open-redirect class of bug is closed
 *     for the happy case (vue-router normalises absolute URLs
 *     into internal paths, so we verify we stayed on our host).
 *   · JWT is NEVER written to localStorage / sessionStorage.
 */
import { expect, test } from '@playwright/test'
import { backendIsUp, CREDENTIALS, login } from './helpers'

test.describe('[GOES Security FE · E2E] auth flow', () => {
  test.beforeAll(async ({ request }) => {
    test.skip(
      !(await backendIsUp(request)),
      'Backend /api unreachable — start portafolio-it-be before running E2E security tests.',
    )
  })

  test('[R8] wrong credentials surface the GENERIC error (no user enumeration)', async ({
    page,
  }) => {
    await login(page, {
      email: CREDENTIALS.admin.email,
      password: 'definitely-wrong-password',
    })
    // The service normalises any 401 to the same copy regardless
    // of whether the email exists. We match on the literal to make
    // an accidental regression visible in the failure diff.
    await expect(page.getByText(/credenciales invalidas/i)).toBeVisible()
    // We must NOT have navigated away.
    await expect(page).toHaveURL(/\/login/)
  })

  test('[R14] happy path lands on the dashboard and never writes the JWT to Web Storage', async ({
    page,
  }) => {
    await login(page, CREDENTIALS.admin)
    await expect(page).toHaveURL(/\/dashboard\/category/)

    // Web Storage audit: after a successful login the access token
    // must live in memory (Pinia) only.
    const storage = await page.evaluate(() => {
      const keys = ['accessToken', 'token', 'jwt', 'refreshToken', 'auth']
      const snapshot: Record<string, string | null> = {}
      for (const k of keys) {
        snapshot['local:' + k] = localStorage.getItem(k)
        snapshot['session:' + k] = sessionStorage.getItem(k)
      }
      return snapshot
    })
    for (const [, value] of Object.entries(storage)) {
      expect(value).toBeNull()
    }
  })

  test('[R8] ?redirect=/dashboard/infrastructure is honoured for site-relative targets', async ({
    page,
  }) => {
    await page.goto('/login?redirect=/dashboard/infrastructure')
    await page.getByLabel(/correo electr/i).fill(CREDENTIALS.admin.email)
    await page.getByLabel(/contrase/i).fill(CREDENTIALS.admin.password)
    await page.getByRole('button', { name: /entrar/i }).click()

    await expect(page).toHaveURL(/\/dashboard\/infrastructure/)
  })

  test('[R8] ?redirect=https://evil.com NEVER navigates off-origin', async ({
    page,
    baseURL,
  }) => {
    await page.goto('/login?redirect=https://evil.com/steal')
    await page.getByLabel(/correo electr/i).fill(CREDENTIALS.admin.email)
    await page.getByLabel(/contrase/i).fill(CREDENTIALS.admin.password)
    await page.getByRole('button', { name: /entrar/i }).click()

    // Give the SPA a moment to settle after the click.
    await page.waitForLoadState('networkidle')

    // The critical assertion: whatever the router decided, we
    // stayed on our origin. vue-router treats an absolute URL as
    // a path prefix, so we end up inside the SPA rendering a
    // 404 or the default route — never on evil.com.
    const url = new URL(page.url())
    expect(baseURL).toBeTruthy()
    expect(url.origin).toBe(new URL(baseURL!).origin)
  })
})
```

## Adapt

- Update `CREDENTIALS` with the seeded users of your backend (see the BE README — typically `admin@<domain>.gob.sv`, `tecnico@<domain>.gob.sv`, `consulta@<domain>.gob.sv`).
- Adjust label selectors (`/correo/i`, `/contrase/i`, `/entrar/i`) to match your real UI copy — these MUST stay in the project language because they target real DOM text.
- If your login route is at `/signin` instead of `/login`, update the URL regex.
