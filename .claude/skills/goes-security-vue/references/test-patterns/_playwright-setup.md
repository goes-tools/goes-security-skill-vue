# Playwright E2E Setup — For patterns that need a running SPA + backend

Some security behaviors can only be verified with the app actually running in a browser: login flow end-to-end, RBAC enforcement against a real backend, logout invalidating the refresh cookie server-side.

## Which patterns need Playwright?

| Pattern | Why |
|---------|-----|
| 14 — E2E auth flow | Need a real browser to exercise the login form, credentials validation, open-redirect guard |
| 15 — E2E RBAC enforcement | Need real user sessions (admin / técnico / viewer) against the backend |
| 16 — E2E session lifecycle | Need to verify logout invalidates the refresh cookie server-side, not only in-memory state |

## `playwright.config.ts`

```typescript
import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://127.0.0.1:5173',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1 --port 5173',
    url: 'http://127.0.0.1:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
```

Add script:

```json
{
  "scripts": {
    "test:e2e": "playwright test"
  }
}
```

## Helpers — `tests/e2e/helpers.ts`

```typescript
import { expect, type APIRequestContext, type Page } from '@playwright/test'

/** Seeded credentials from the backend README. Adjust to your project. */
export const CREDENTIALS = {
  admin:   { email: 'admin@example.gob.sv',   password: 'AdminXXX!' },
  tecnico: { email: 'tecnico@example.gob.sv', password: 'TecnicoXXX!' },
  viewer:  { email: 'viewer@example.gob.sv',  password: 'ViewerXXX!' },
} as const

/**
 * True when the backend `/api/auth/session` responds (any status).
 * Use it to `test.skip()` the whole suite if the BE is not running —
 * that way CI without the stack still passes with 0 tests instead
 * of a wall of red X.
 */
export async function backendIsUp(request: APIRequestContext): Promise<boolean> {
  try {
    const res = await request.get('/api/auth/session', {
      timeout: 3_000,
      failOnStatusCode: false,
    })
    return res.status() > 0
  } catch {
    return false
  }
}

export async function login(
  page: Page,
  creds: { email: string; password: string },
): Promise<void> {
  await page.goto('/login')
  await page.getByLabel(/correo|email/i).fill(creds.email)
  await page.getByLabel(/contrase|password/i).fill(creds.password)
  await page.getByRole('button', { name: /entrar|sign in/i }).click()
}
```

## Skip pattern per spec

Every E2E security spec starts with:

```typescript
test.describe('[GOES Security FE · E2E] ...', () => {
  test.beforeAll(async ({ request }) => {
    test.skip(
      !(await backendIsUp(request)),
      'Backend /api unreachable — start the backend before running E2E security tests.',
    )
  })

  // tests here
})
```

This keeps CI green when the backend is not running, while still exercising the full stack when it is.
