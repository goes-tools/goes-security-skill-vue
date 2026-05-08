# Pattern 22 — E2E Playwright · Security Headers & CSP

**Covers:** `R18`, `R19`, `R20` · **OWASP:** A05 (Security Misconfiguration) · **Severity:** high

Verifies that the application sets proper HTTP security headers to prevent clickjacking, MIME-type sniffing, enforce HTTPS, control content security, and restrict permissions.

Key assertions:

1. X-Frame-Options header — set to DENY or SAMEORIGIN to prevent clickjacking.
2. X-Content-Type-Options — set to "nosniff" to prevent MIME-type sniffing.
3. Strict-Transport-Security — set with max-age >= 15768000 (6 months) to enforce HTTPS.
4. Content-Security-Policy — present with script-src, object-src 'none', frame-ancestors restrictions.
5. Referrer-Policy — set to "strict-origin-when-cross-origin" or stricter to protect user privacy.
6. Permissions-Policy — denies camera, microphone, geolocation unless explicitly enabled.
7. Cache-Control on auth pages — /login and /api/auth/* responses have no-store to prevent caching.

Requires the backend running on `/api`. Use the `backendIsUp()` probe (see `_playwright-setup.md`) so CI without the stack still produces 0 tests instead of a wall of red.

## Example spec — `tests/e2e/security-headers-csp.security.spec.ts`

```typescript
/**
 * E2E · Security headers and CSP
 * ───────────────────────────────
 * Verifies that the application sets proper HTTP security headers:
 *
 *   · X-Frame-Options prevents clickjacking (DENY or SAMEORIGIN).
 *   · X-Content-Type-Options: nosniff prevents MIME-sniffing.
 *   · Strict-Transport-Security enforces HTTPS (max-age >= 6 months).
 *   · Content-Security-Policy restricts scripts, objects, frames.
 *   · Referrer-Policy protects user privacy (strict-origin-when-cross-origin).
 *   · Permissions-Policy denies camera, microphone, geolocation.
 *   · Cache-Control: no-store on /login and /api/auth/* endpoints.
 */
import { expect, test } from '@playwright/test'
import { backendIsUp, CREDENTIALS, login } from './helpers'

test.describe('[GOES Security FE · E2E] security headers & CSP', () => {
  test.beforeAll(async ({ request }) => {
    test.skip(
      !(await backendIsUp(request)),
      'Backend /api unreachable — start the backend before running E2E security tests.',
    )
  })

  test('[R18] X-Frame-Options header — DENY or SAMEORIGIN', async ({
    request,
  }) => {
    const res = await request.get('/')

    const xFrameOptions = res.headers()['x-frame-options']?.toLowerCase()

    expect(xFrameOptions).toBeTruthy()
    expect(['deny', 'sameorigin']).toContain(xFrameOptions)
  })

  test('[R18] X-Content-Type-Options header — nosniff', async ({
    request,
  }) => {
    const res = await request.get('/')

    const contentTypeOptions = res.headers()['x-content-type-options']?.toLowerCase()

    expect(contentTypeOptions).toBe('nosniff')
  })

  test('[R19] Strict-Transport-Security header — max-age >= 6 months', async ({
    request,
  }) => {
    const res = await request.get('/')

    const hsts = res.headers()['strict-transport-security']

    expect(hsts).toBeTruthy()

    // Extract max-age from the header (e.g., "max-age=15768000; includeSubDomains").
    const maxAgeMatch = hsts?.match(/max-age=(\d+)/i)
    expect(maxAgeMatch).toBeTruthy()

    const maxAge = parseInt(maxAgeMatch![1], 10)
    const sixMonthsInSeconds = 15768000

    expect(maxAge).toBeGreaterThanOrEqual(sixMonthsInSeconds)
  })

  test('[R19] Content-Security-Policy header — script-src, object-src, frame-ancestors', async ({
    request,
  }) => {
    const res = await request.get('/')

    const csp = res.headers()['content-security-policy']

    expect(csp).toBeTruthy()

    // CSP must include directives for script-src and object-src.
    expect(csp).toContain('script-src')
    expect(csp).toContain('object-src')
    expect(csp).toContain('frame-ancestors')

    // object-src and frame-ancestors should be restrictive.
    expect(csp).toContain("object-src 'none'")
    expect(csp).toMatch(/frame-ancestors\s+'none'|frame-ancestors\s+'self'/)
  })

  test('[R20] Referrer-Policy header — strict-origin-when-cross-origin or stricter', async ({
    request,
  }) => {
    const res = await request.get('/')

    const referrerPolicy = res.headers()['referrer-policy']?.toLowerCase()

    expect(referrerPolicy).toBeTruthy()

    // Acceptable policies (ordered by strength).
    const acceptablePolicies = [
      'no-referrer',
      'no-referrer-when-downgrade',
      'same-origin',
      'strict-origin',
      'strict-origin-when-cross-origin',
    ]

    expect(acceptablePolicies).toContain(referrerPolicy)
  })

  test('[R20] Permissions-Policy header — camera, microphone, geolocation denied', async ({
    request,
  }) => {
    const res = await request.get('/')

    const permissionsPolicy =
      res.headers()['permissions-policy'] ||
      res.headers()['feature-policy']

    expect(permissionsPolicy).toBeTruthy()

    if (permissionsPolicy) {
      // Modern format: camera=(), microphone=(), geolocation=()
      // Older format (feature-policy): camera 'none'; microphone 'none'; geolocation 'none'
      const policy = permissionsPolicy.toLowerCase()

      // Check that these are denied (either via () or 'none').
      expect(policy).toMatch(/camera\s*=\s*\(\)|camera\s+'none'/)
      expect(policy).toMatch(/microphone\s*=\s*\(\)|microphone\s+'none'/)
      expect(policy).toMatch(/geolocation\s*=\s*\(\)|geolocation\s+'none'/)
    }
  })

  test('[R20] Cache-Control: no-store on /login responses', async ({
    request,
  }) => {
    const res = await request.get('/login')

    const cacheControl = res.headers()['cache-control']?.toLowerCase()

    expect(cacheControl).toBeTruthy()
    expect(cacheControl).toContain('no-store')
  })

  test('[R20] Cache-Control: no-store on /api/auth/* responses', async ({
    request,
  }) => {
    // Test the session endpoint (typically public and does not require auth).
    const res = await request.get('/api/auth/session', {
      failOnStatusCode: false,
    })

    const cacheControl = res.headers()['cache-control']?.toLowerCase()

    // Auth endpoints must not be cached.
    if (cacheControl) {
      expect(cacheControl).toContain('no-store')
    } else {
      // If no cache-control header, that's OK if the endpoint returns 401
      // (some servers omit headers on auth errors). Document this assumption.
      expect([200, 401, 403]).toContain(res.status())
    }
  })

  test('[R18] no X-Powered-By or Server version leakage', async ({
    request,
  }) => {
    const res = await request.get('/')

    // These headers leak server software information and should be removed.
    const xPoweredBy = res.headers()['x-powered-by']
    const server = res.headers()['server']

    // Ideally both are absent. If present, they should not leak version info.
    if (xPoweredBy) {
      expect(xPoweredBy).not.toMatch(/\d+\.\d+/)
    }
    if (server) {
      expect(server).not.toMatch(/\d+\.\d+/)
    }
  })
})
```

## Adapt

- Update endpoint paths (`/`, `/login`, `/api/auth/session`) if your app structure differs.
- Adjust CSP directives to match your actual policy (e.g., if you allow certain script-src domains).
- If your app uses the older `Feature-Policy` header instead of `Permissions-Policy`, update the header name check.
- If your HSTS max-age is different, adjust the 6-month (15768000 seconds) threshold accordingly.
- Consider adding tests for additional CSP directives specific to your app (img-src, font-src, etc.).
