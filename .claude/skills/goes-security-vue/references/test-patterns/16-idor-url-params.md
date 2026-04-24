# Pattern 16 — IDOR via URL Params

**Covers:** `R23` · **OWASP:** A01 · **Severity:** blocker

The SPA itself cannot PREVENT IDOR (ultimately the backend is the authority on "does this user own that record?"). What the SPA can and MUST do:

1. Never render privileged data when the API responds with 403 / 404 — show `/forbidden` or a sanitized "not found" instead of blindly trusting the router param.
2. Never use the URL param (`/users/:id/edit`) as the source of truth for "this is my user". Always cross-check against the authenticated identity stored in Pinia.
3. Avoid building UIs that encourage param tampering (e.g. numeric ids auto-incremented in the URL).

## Example spec — `tests/security/idor-url-params.security-html.spec.ts`

```typescript
/**
 * IDOR via URL params — defensive UI behavior
 * ────────────────────────────────────────────
 * Two assertions around resources addressed by `:id` in the URL:
 *
 *   1. If the backend responds 403/404, the view does NOT render
 *      privileged data. It surfaces an error instead.
 *   2. The view cross-checks the URL id against the authenticated
 *      user id when the flow is supposedly "my profile". A guard
 *      that only checks `to.params.id === store.user.id` catches
 *      accidental links but an audit test proves the guard exists.
 */
import { describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { AxiosError } from 'axios'
import { report } from '@security-reporter/metadata'
import { api } from '@/lib/api/client'
import { useAuthStore } from '@/features/auth/stores/auth.store'
// Adapt to the actual service / composable under test.
import { userService } from '@/features/users/services/user.service'

describe('[GOES Security FE] IDOR guard · URL params', () => {
  it('[R23] 403 from /users/:id does NOT surface user data to the caller', async () => {
    const t = report()
    t.epic('IDOR Prevention')
    t.feature('URL params are untrusted')
    t.story('Backend 403 → empty UI, not the target user')
    t.severity('blocker')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R23')
    t.descriptionHtml(
      '<p>If an attacker rewrites <code>/users/42</code> to ' +
        '<code>/users/43</code> and the backend responds 403, the view ' +
        'must treat the 403 as the end of the story — NOT silently ' +
        'fall back to "cached" data from the previous navigation.</p>',
    )

    const err = new AxiosError('forbidden')
    ;(err as { response?: unknown }).response = { status: 403, data: {} }
    vi.spyOn(api, 'get').mockRejectedValueOnce(err)

    await expect(userService.getById('43')).rejects.toBeTruthy()

    // The service must NOT resolve with partial or cached data.
    // If the real service catches 403 and returns `null`, update
    // the assertion to `.resolves.toBeNull()` — but NEVER allow it
    // to return someone else's user object.
    await t.flush()
  })

  it('[R23] "my profile" route must cross-check URL id against store', async () => {
    const t = report()
    t.epic('IDOR Prevention')
    t.feature('Self-only routes')
    t.story('Cannot open /profile/99 while logged in as user 42')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R23')
    t.descriptionHtml(
      '<p>A route labeled as "my profile" must not honour an arbitrary ' +
        'id in the URL. Trusting the URL here is exactly the bug IDOR ' +
        'checks prevent.</p>',
    )

    setActivePinia(createPinia())
    const auth = useAuthStore()
    auth.setSession({
      accessToken: 'tk',
      accessExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      idleExpiresAt: new Date(Date.now() + 25 * 60_000).toISOString(),
      user: { id: '42', email: 'u42@x', name: 'User 42', roles: ['usuario'], perfil: 'usuario', rol: 'Consulta' },
    })

    // The helper below is what the router guard or the view should
    // implement. If your project has a `canAccessProfile(id)` guard,
    // import and assert on it directly.
    const canAccessProfile = (urlId: string) =>
      useAuthStore().user?.id === urlId

    expect(canAccessProfile('42')).toBe(true)
    expect(canAccessProfile('99')).toBe(false)

    await t.flush()
  })
})
```

## Adapt

- Point the import at the real service / composable (`userService`, `orderService`, whatever the project calls it).
- If the project exposes a `canAccessProfile(id)` guard, import it directly instead of defining the helper locally — that turns the test into a contract test for the real guard.
- Extend with every resource type the SPA exposes by URL id (orders, documents, tickets...).
