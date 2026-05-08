# Pattern 23 — E2E Playwright · Error Pages (403/404) & Information Leakage

**Covers:** `R21`, `R22`, `R30` · **OWASP:** A05, A09 · **Severity:** high

Verifies that error pages do not leak sensitive information (stack traces, file paths, server version) and that common attack vectors (path traversal, directory listing) are blocked.

Key assertions:

1. Unknown route shows custom 404 page (not framework default).
2. Forbidden page (403) does not leak role requirements or internal details.
3. Error pages never show stack traces or file paths (test with path traversal URLs too).
4. Response headers don't reveal server version (X-Powered-By removed).
5. API error responses use consistent format without internal details.
6. Path traversal attempts (../../etc/passwd) return 400/404, never file contents.
7. /dashboard without auth shows login redirect, not error crash.
8. Auth failure API responses don't leak user existence info.

Requires the backend running on `/api`. Use the `backendIsUp()` probe (see `_playwright-setup.md`) so CI without the stack still produces 0 tests instead of a wall of red.

## Example spec — `tests/e2e/error-pages-404-403.security.spec.ts`

```typescript
/**
 * E2E · Error pages and information leakage
 * ──────────────────────────────────────────
 * Verifies that error pages do not leak sensitive information:
 *
 *   · Unknown routes show a custom 404, not the framework default.
 *   · 403 pages do not expose role requirements or internals.
 *   · Stack traces and file paths are never shown in error pages.
 *   · Path traversal (../../etc/passwd) returns 400/404, not contents.
 *   · Response headers don't leak server version info.
 *   · API errors use a consistent format without internal details.
 *   · Auth redirects don't crash (graceful 302 to /login).
 *   · Failed login never leaks whether a user exists.
 */
import { expect, test } from '@playwright/test'
import { backendIsUp, CREDENTIALS } from './helpers'

test.describe('[GOES Security FE · E2E] error pages & information leakage', () => {
  test.beforeAll(async ({ request }) => {
    test.skip(
      !(await backendIsUp(request)),
      'Backend /api unreachable — start the backend before running E2E security tests.',
    )
  })

  test('[R21] unknown route shows custom 404 page (not framework default)', async ({
    page,
  }) => {
    // Navigate to a non-existent route.
    await page.goto('/this-route-does-not-exist-abc123', {
      waitUntil: 'networkidle',
    })

    // The page should show a custom 404, not the Vue/Vite default.
    // Look for common custom 404 patterns (your app's text).
    const pageContent = await page.textContent('body')

    // Avoid matching framework defaults like "Cannot GET /path" or "404 Not Found"
    // that come from Express or webpack defaults.
    expect(pageContent).not.toMatch(/cannot get\/this-route/i)

    // Your custom 404 might have copy like:
    // "Página no encontrada", "404", "La página solicitada no existe"
    // Adjust the assertion to match your actual error page.
    expect(pageContent).toMatch(/no encontrada|página|error/i)
  })

  test('[R21] forbidden page does not leak role requirements', async ({
    page,
  }) => {
    // Navigate to a route that requires special roles (403).
    // Assuming /dashboard/admin requires ADMIN role.
    await page.goto('/dashboard/admin', { waitUntil: 'networkidle' })

    const pageContent = await page.textContent('body')

    // The error page must NOT reveal what roles are required.
    // Bad: "This page requires ADMIN or SUPER_ADMIN role"
    // Good: "You don't have permission to view this page"
    expect(pageContent).not.toMatch(/admin|super_admin|tecnico|viewer/i)
    expect(pageContent).not.toMatch(/required roles?:/i)
    expect(pageContent).not.toMatch(/permission denied.*because/i)
  })

  test('[R30] error pages never show stack traces or file paths', async ({
    page,
  }) => {
    // Navigate to a non-existent route.
    await page.goto('/not-a-route', { waitUntil: 'networkidle' })

    const pageContent = await page.textContent('body')
    const pageHTML = await page.locator('body').innerHTML()

    // Must NOT contain stack traces or file paths.
    expect(pageContent).not.toMatch(/at\s+\w+.*\(/m) // Stack frame pattern
    expect(pageContent).not.toMatch(/\/src\/\w+\.(js|ts)/i) // File paths
    expect(pageContent).not.toMatch(/Error:/i) // Generic error prefix
    expect(pageContent).not.toMatch(/ReferenceError|TypeError|SyntaxError/i)

    // HTML should not contain <pre><code> tags with stack traces.
    expect(pageHTML).not.toContain('<pre')
  })

  test('[R30] path traversal attempts return 400/404, not file contents', async ({
    page,
    request,
  }) => {
    // Test various path traversal patterns.
    const traversalPaths = [
      '../../etc/passwd',
      '../../../windows/system32/config/sam',
      '../../.env',
      '../../../app.config.json',
    ]

    for (const path of traversalPaths) {
      const res = await request.get(`/${path}`, {
        failOnStatusCode: false,
      })

      // Must return 4xx error, never 200.
      expect([400, 404]).toContain(res.status())

      // Response body must not contain sensitive files.
      const body = await res.text()
      expect(body).not.toContain('root:x:0:0')
      expect(body).not.toContain('Administrator')
      expect(body).not.toContain('DATABASE_URL')
    }
  })

  test('[R21] response headers do not leak server version', async ({
    request,
  }) => {
    const res = await request.get('/')

    // Check for server version leakage.
    const serverHeader = res.headers()['server']
    const xPoweredBy = res.headers()['x-powered-by']

    // These headers should either be absent or not contain version numbers.
    if (serverHeader) {
      // Bad: "Apache/2.4.41", "nginx/1.18.0"
      // OK: "Apache", "nginx" (no version)
      expect(serverHeader).not.toMatch(/\d+\.\d+/)
    }

    if (xPoweredBy) {
      expect(xPoweredBy).not.toMatch(/\d+\.\d+/)
    }
  })

  test('[R22] API error responses use consistent format without internals', async ({
    request,
  }) => {
    // Call a non-existent API endpoint.
    const res = await request.get('/api/this-does-not-exist', {
      failOnStatusCode: false,
    })

    // Should return a 4xx error.
    expect(res.status()).toBeGreaterThanOrEqual(400)
    expect(res.status()).toBeLessThan(500)

    // Response should be a consistent error format (e.g., JSON).
    const body = await res.json().catch(() => ({}))

    // Check that the error object has a predictable shape.
    // Common patterns: { error: "...", message: "..." } or
    // { status: 404, message: "..." }
    if (body && typeof body === 'object') {
      // Must NOT contain stack traces or file paths.
      const errorText = JSON.stringify(body)
      expect(errorText).not.toMatch(/\/src\/\w+\.(js|ts)/i)
      expect(errorText).not.toMatch(/at\s+\w+\s+/m)
    }
  })

  test('[R21] /dashboard without auth redirects to /login (no crash)', async ({
    page,
  }) => {
    // Access a private route without authentication.
    // The app should gracefully redirect to /login, not crash.
    await page.goto('/dashboard/category')

    // Verify we're redirected to login.
    await expect(page).toHaveURL(/\/login/)

    // The page should render cleanly, not show an error.
    const pageContent = await page.textContent('body')
    expect(pageContent).not.toMatch(/error|exception|crash/i)
  })

  test('[R22] auth failure API responses do not leak user existence', async ({
    request,
  }) => {
    // Test with a non-existent email.
    const res1 = await request.post('/api/auth/login', {
      data: {
        email: 'nonexistent@example.gob.sv',
        password: 'password123',
      },
      failOnStatusCode: false,
    })

    // Test with an existing email (from CREDENTIALS) but wrong password.
    const res2 = await request.post('/api/auth/login', {
      data: {
        email: CREDENTIALS.admin.email,
        password: 'wrong-password',
      },
      failOnStatusCode: false,
    })

    // Both must return the same HTTP status code and message (no enumeration).
    expect(res1.status()).toBe(res2.status())

    const body1 = await res1.json().catch(() => ({}))
    const body2 = await res2.json().catch(() => ({}))

    // Error messages must be identical (generic).
    // Good: "Invalid credentials"
    // Bad: "User not found" vs "Wrong password"
    if (body1.message && body2.message) {
      expect(body1.message).toBe(body2.message)
    }
  })

  test('[R30] error pages do not contain debug/development-only info', async ({
    page,
  }) => {
    // Navigate to a 404.
    await page.goto('/nonexistent-page', { waitUntil: 'networkidle' })

    const pageContent = await page.textContent('body')

    // Must NOT show development-only info.
    expect(pageContent).not.toContain('process.env')
    expect(pageContent).not.toContain('NODE_ENV')
    expect(pageContent).not.toContain('__vite_')
    expect(pageContent).not.toContain('sourceMap')
    expect(pageContent).not.toMatch(/webpack|vite/i)
  })
})
```

## Adapt

- Update the 404 route test assertion to match your app's actual custom error page copy (e.g., Spanish labels like "Página no encontrada").
- If your forbidden route is different from `/dashboard/admin`, adjust the URL accordingly.
- For the path traversal test, add or remove paths based on your backend framework (e.g., .htaccess, .git, .env).
- If your API error response format differs (e.g., `{ errors: [...] }` instead of `{ message: "..." }`), update the response validation.
- Adjust the existence-enumeration test to use actual endpoints and response shapes from your backend.
- If your error pages legitimately contain certain keywords (e.g., "error" as part of a page title), refine the regex accordingly.
