# Pattern 11 — E2E Playwright · RBAC Enforcement

**Covers:** `R9`, `R24`, `R34`, `VF8` · **OWASP:** A01 · **Severity:** blocker

Proves that the router guard blocks routes whose `meta.roles` does not intersect the current user's roles. One test per profile × restricted route combination catches the top RBAC regression: a new route is added but someone forgets the `roles` meta entry.

Typical matrix:

| Profile | Admin route | Tecnico route | Viewer route |
|---------|-------------|---------------|--------------|
| admin   | OK          | OK            | OK           |
| técnico | /forbidden  | OK            | OK           |
| viewer  | /forbidden  | /forbidden    | OK           |

## Example spec — `tests/e2e/rbac.security.spec.ts`

```typescript
/**
 * E2E · RBAC enforcement at the router
 * ──────────────────────────────────────
 * Proves the router guard blocks routes whose `meta.roles` does
 * not intersect the user's `roles`. Three profiles exercise the
 * full matrix:
 *
 *   · Admin        → /dashboard/maintainer OK
 *   · Técnico      → /dashboard/maintainer → /forbidden
 *   · Viewer       → /dashboard/maintainer → /forbidden
 *                  AND /dashboard/infrastructure → /forbidden
 *
 * This catches the top RBAC regression: a new route is added
 * but someone forgets the `roles` meta entry.
 */
import { expect, test } from '@playwright/test'
import { backendIsUp, CREDENTIALS, login } from './helpers'

test.describe('[GOES Security FE · E2E] RBAC · router guard', () => {
  test.beforeAll(async ({ request }) => {
    test.skip(
      !(await backendIsUp(request)),
      'Backend /api unreachable — start portafolio-it-be before running E2E security tests.',
    )
  })

  test('[R9] ADMIN reaches /dashboard/maintainer', async ({ page }) => {
    await login(page, CREDENTIALS.admin)
    await expect(page).toHaveURL(/\/dashboard\/category/)

    await page.goto('/dashboard/maintainer')
    await expect(page).toHaveURL(/\/dashboard\/maintainer/)
  })

  test('[R9] TECNICO attempting /dashboard/maintainer lands on /forbidden', async ({
    page,
  }) => {
    await login(page, CREDENTIALS.tecnico)
    await expect(page).toHaveURL(/\/dashboard\/category/)

    await page.goto('/dashboard/maintainer')
    // Router must redirect, not render the maintainer view.
    await expect(page).toHaveURL(/\/dashboard\/forbidden/)
  })

  test('[R9] VIEWER is blocked from maintainer AND infrastructure', async ({
    page,
  }) => {
    await login(page, CREDENTIALS.viewer)
    await expect(page).toHaveURL(/\/dashboard\/category/)

    await page.goto('/dashboard/maintainer')
    await expect(page).toHaveURL(/\/dashboard\/forbidden/)

    await page.goto('/dashboard/infrastructure')
    await expect(page).toHaveURL(/\/dashboard\/forbidden/)
  })
})
```

## Adapt

- Update route paths (`/dashboard/maintainer`, `/dashboard/infrastructure`) to the real restricted routes.
- If your app has more than 3 roles, expand the matrix accordingly.
- If the "forbidden" page has a different URL (e.g. `/403`), update the `toHaveURL` regex.
