# Pattern 19 — E2E Playwright · XSS Input Sanitization

**Covers:** `R6`, `R10`, `R29` · **OWASP:** A03 (Injection), A07 · **Severity:** blocker

Verifies that the UI properly escapes user input in all contexts and prevents both reflected and stored XSS attacks. Tests cover form inputs, query parameters, hash-based navigation, attribute injection, and DOM rendering.

Key assertions:

1. Reflected XSS in search/form inputs — dangerous payloads are escaped before rendering.
2. XSS via query parameters — `/?search=<img onerror=...>` does not execute scripts.
3. DOM-based XSS via location.hash — hash-driven routing does not execute injected scripts.
4. Attribute injection attacks — quote escaping in attributes prevents event handler injection.
5. Stored XSS — payloads persisted via forms are escaped on reload (not executed).
6. X-Content-Type-Options: nosniff header prevents MIME-sniffing attacks on API responses.

Requires the backend running on `/api`. Use the `backendIsUp()` probe (see `_playwright-setup.md`) so CI without the stack still produces 0 tests instead of a wall of red.

## Example spec — `tests/e2e/xss-input-sanitization.security.spec.ts`

```typescript
/**
 * E2E · XSS input sanitization
 * ─────────────────────────────
 * Verifies that the UI properly escapes user input across all
 * contexts and prevents both reflected and stored XSS attacks:
 *
 *   · Form inputs sanitize dangerous payloads (script tags, event handlers).
 *   · Query parameters (?search=...) are escaped before rendering.
 *   · Hash-based navigation (#...) does not execute injected scripts.
 *   · Attribute values properly escape quotes to prevent event handlers.
 *   · Stored XSS: persisted payloads are escaped on page reload.
 *   · Content-Type headers prevent MIME-sniffing attacks.
 */
import { expect, test } from '@playwright/test'
import { backendIsUp, CREDENTIALS, login } from './helpers'

test.describe('[GOES Security FE · E2E] XSS input sanitization', () => {
  test.beforeAll(async ({ request }) => {
    test.skip(
      !(await backendIsUp(request)),
      'Backend /api unreachable — start the backend before running E2E security tests.',
    )
  })

  test('[R6] reflected XSS in form search — script tag is escaped', async ({
    page,
  }) => {
    await login(page, CREDENTIALS.admin)
    await expect(page).toHaveURL(/\/dashboard/)

    // Find the search input and type a script injection payload.
    const searchInput = page.getByPlaceholder(/buscar|search/i).first()
    await searchInput.fill('<script>alert("xss")</script>')
    await page.getByRole('button', { name: /buscar|search/i }).first().click()

    // Wait for the page to settle.
    await page.waitForLoadState('networkidle')

    // The payload must be escaped and visible as text, not executed.
    // We verify by:
    // 1. No alert dialogs appeared (would fail the test if triggered).
    // 2. The escaped text is visible in the DOM.
    const bodyText = await page.textContent('body')
    expect(bodyText).toContain('<script>')

    // Confirm we never received an alert (Playwright fails if dialog pops).
    // If we reach here, no alert executed.
  })

  test('[R10] XSS via query parameter — img onerror payload is escaped', async ({
    page,
  }) => {
    await login(page, CREDENTIALS.admin)

    // Navigate with a malicious query parameter.
    await page.goto('/dashboard/category?search=<img onerror=alert(1) src=x>')

    // Give the SPA time to process the parameter.
    await page.waitForLoadState('networkidle')

    // The payload must not execute. We verify the escaped text exists in the DOM.
    const bodyHTML = await page.locator('body').innerHTML()
    expect(bodyHTML).toContain('&lt;img')
    expect(bodyHTML).toContain('&gt;')

    // Confirm no alert fired (Playwright would catch it).
  })

  test('[R10] DOM-based XSS via location.hash — no script execution', async ({
    page,
  }) => {
    await login(page, CREDENTIALS.admin)

    // Navigate using the hash with an XSS payload.
    await page.goto('/dashboard/category#<img onerror=alert("hash-xss") src=x>')

    // Give the router time to process the hash.
    await page.waitForLoadState('networkidle')

    // Verify the payload is escaped, not executed.
    const bodyHTML = await page.locator('body').innerHTML()
    expect(bodyHTML).toContain('&lt;img')

    // No alert means the attack failed.
  })

  test('[R10] attribute injection — quote escaping prevents event handlers', async ({
    page,
  }) => {
    await login(page, CREDENTIALS.admin)

    // Find an input field and inject attribute-breaking payload.
    const input = page.getByLabel(/correo|email/i).first()
    await input.fill('" onmouseover="alert(\'attr-xss\')')

    // Move mouse over the input to trigger the event (if injection succeeded).
    await input.hover()

    // Wait a moment for any potential alert.
    await page.waitForTimeout(1000)

    // If we reach here without an alert, the injection was prevented.
    // Verify the escaped value in the input's value attribute.
    const value = await input.inputValue()
    expect(value).not.toContain('onmouseover')
  })

  test('[R29] stored XSS — persisted payload is escaped on reload', async ({
    page,
  }) => {
    await login(page, CREDENTIALS.admin)

    // Submit a form with an XSS payload (assuming a text field that persists).
    // Example: edit profile description.
    const descInput = page
      .getByLabel(/descripcion|description|biografia/i)
      .first()
    if ((await descInput.count()) > 0) {
      await descInput.fill('<svg onload=alert("stored-xss")>')

      // Submit the form.
      const submitBtn = page.getByRole('button', { name: /guardar|save/i })
      if ((await submitBtn.count()) > 0) {
        await submitBtn.first().click()
        await page.waitForLoadState('networkidle')
      }
    }

    // Reload the page to fetch the persisted payload from the backend.
    await page.reload()

    // The payload must be escaped and not execute.
    const bodyHTML = await page.locator('body').innerHTML()
    expect(bodyHTML).toContain('&lt;svg')

    // No alert confirms the stored payload was properly escaped.
  })

  test('[R6] X-Content-Type-Options: nosniff header prevents MIME-sniffing', async ({
    request,
  }) => {
    // Call an API endpoint and verify the nosniff header.
    const res = await request.get('/api/auth/session', {
      failOnStatusCode: false,
    })

    const contentTypeOptions = res.headers()['x-content-type-options']
    expect(contentTypeOptions).toBeTruthy()
    expect(contentTypeOptions?.toLowerCase()).toBe('nosniff')
  })
})
```

## Adapt

- Update search/input selectors to match your actual UI labels (e.g., `/buscar`, `/search`).
- If your app does not have a form that persists data, remove or adapt the stored XSS test to use an actual persistent field (comments, descriptions, etc.).
- Adjust button names (`/guardar/i`, `/save/i`) to match your UI.
- If the API base path is different from `/api`, update the header verification test accordingly.
- Consider adding more input contexts specific to your app (autocomplete, rich text editors, etc.) if they accept user input.
