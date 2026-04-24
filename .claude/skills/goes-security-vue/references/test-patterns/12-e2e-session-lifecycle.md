# Pattern 12 — E2E Playwright · Session Lifecycle

**Covers:** `R35`, `R40`, `VF4` · **OWASP:** A04, A07 · **Severity:** critical

Two ends of the session story:

1. Unauthenticated visit of a private URL redirects to `/login?redirect=<original>` with the path URL-encoded.
2. Logout invalidates the refresh cookie **server-side** — a subsequent visit to a private URL must NOT resurrect the session. This specifically catches the bug where the Pinia state is cleared but the httpOnly cookie still works (interceptor silently re-auths).

## Example spec — `tests/e2e/session.security.spec.ts`

```typescript
/**
 * E2E · Session management
 * ─────────────────────────
 *   · Logout drops the Pinia token AND the httpOnly refresh
 *     cookie is cleared by the backend (so a subsequent
 *     /dashboard/* visit bounces to /login).
 *   · Accessing a private URL without a session redirects to
 *     /login with the original path preserved in ?redirect=
 *     (open-redirect vector tested in auth-flow.security).
 *   · Directly navigating to /dashboard after logout does NOT
 *     resurrect the previous session (proves the refresh cookie
 *     was actually killed server-side on logout, not only
 *     cleared in Pinia).
 */
import { expect, test } from '@playwright/test'
import { backendIsUp, CREDENTIALS, login } from './helpers'

test.describe('[GOES Security FE · E2E] session lifecycle', () => {
  test.beforeAll(async ({ request }) => {
    test.skip(
      !(await backendIsUp(request)),
      'Backend /api unreachable — start portafolio-it-be before running E2E security tests.',
    )
  })

  test('[R40] unauthenticated visit of /dashboard/category redirects to /login?redirect=…', async ({
    page,
  }) => {
    await page.goto('/dashboard/category')
    await expect(page).toHaveURL(
      /\/login\?redirect=.*%2Fdashboard%2Fcategory/,
    )
  })

  test('[R40] logout invalidates the refresh cookie server-side (no resurrection)', async ({
    page,
  }) => {
    await login(page, CREDENTIALS.admin)
    await expect(page).toHaveURL(/\/dashboard\/category/)

    // Find the logout trigger. PrivateLayout exposes it as a
    // button; we match case-insensitive on common copies to stay
    // resilient to small UI tweaks.
    const logoutBtn = page.getByRole('button', {
      name: /cerrar sesi[oó]n|salir|logout/i,
    })
    if (await logoutBtn.count()) {
      await logoutBtn.first().click()
    } else {
      // Fallback: trigger logout via the auth service directly.
      await page.evaluate(async () => {
        const anyWindow = window as unknown as {
          __authService?: { logout?: () => Promise<void> }
        }
        if (anyWindow.__authService?.logout) {
          await anyWindow.__authService.logout()
        }
      })
    }

    // We should end up on /login — either by the UI click or by
    // the subsequent guarded navigation triggering the redirect.
    await page.waitForURL(/\/login/, { timeout: 5_000 }).catch(() => {
      /* tolerate flows that stay put and rely on next nav */
    })

    // Now confirm the ex-session cannot be revived by navigating
    // straight into a private route. If the refresh cookie were
    // still alive the interceptor would silently re-authenticate
    // and we'd end up on /dashboard/category — we do NOT want that.
    await page.goto('/dashboard/category')
    await expect(page).toHaveURL(/\/login/)
  })
})
```

## Adapt

- If the logout button has different copy, update the `name:` regex.
- If the route chain after logout is `/auth/login` instead of `/login`, update the URL regex.
- If the project does NOT use an httpOnly refresh cookie (pure bearer-only) then the "no resurrection" assertion becomes trivial — document it via an N/A entry instead.
