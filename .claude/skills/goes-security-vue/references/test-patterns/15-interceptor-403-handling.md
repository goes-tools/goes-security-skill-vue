# Pattern 15 — API Interceptor · 403 Handling

**Covers:** `VF5` · **OWASP:** A01 · **Severity:** critical

Companion to Pattern 04 (API client defaults). While 401 triggers the refresh flow, a **403** means the server knows who you are AND denies the operation — refreshing won't fix that. The interceptor must:

- NOT retry the request.
- NOT trigger the refresh coordinator.
- Let the error bubble up to the caller OR navigate to `/forbidden` (depending on the project's UX policy).
- NEVER clear the session (403 is not a session problem).

## Example spec — `tests/security/api-client-403.security-html.spec.ts`

```typescript
/**
 * API interceptor — 403 Forbidden handling
 * ─────────────────────────────────────────
 * 403 means authenticated but unauthorised. The interceptor must
 * short-circuit — no refresh attempt, no session wipe, no retry —
 * and either surface the error to the caller or navigate to the
 * /forbidden page. The one thing it MUST NOT do is treat 403 as
 * a session problem.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { AxiosError } from 'axios'
import { report } from '@security-reporter/metadata'
import { api } from '@/lib/api/client'
import { refreshAccessToken } from '@/lib/api/refresh-coordinator'
import { useAuthStore } from '@/features/auth/stores/auth.store'

vi.mock('@/lib/api/refresh-coordinator', () => ({
  refreshAccessToken: vi.fn().mockResolvedValue(null),
  resetRefreshCoordinator: vi.fn(),
}))

afterEach(() => {
  vi.clearAllMocks()
  setActivePinia(createPinia())
})

describe('[GOES Security FE] api interceptor · 403 handling', () => {
  it('[VF5] 403 does NOT trigger the refresh coordinator', async () => {
    const t = report()
    t.epic('Access Control')
    t.feature('Interceptor 403')
    t.story('Forbidden responses never enter the refresh flow')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-VF5')
    t.descriptionHtml(
      '<p>Refreshing a token does not grant the user any new ' +
        'permissions. Firing a refresh on 403 wastes a round-trip and ' +
        'worse, it can mask the real permission bug.</p>',
    )

    const err = new AxiosError('forbidden')
    ;(err as { response?: unknown }).response = {
      status: 403,
      data: { message: 'Insufficient privileges' },
    }
    vi.spyOn(api, 'get').mockRejectedValueOnce(err)

    await expect(api.get('/protected')).rejects.toMatchObject({
      response: { status: 403 },
    })

    expect(refreshAccessToken).not.toHaveBeenCalled()

    await t.flush()
  })

  it('[VF5] 403 does NOT clear the Pinia session', async () => {
    const t = report()
    t.epic('Access Control')
    t.feature('Interceptor 403')
    t.story('Forbidden does not log the user out')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-VF5')

    const auth = useAuthStore()
    auth.setSession({
      accessToken: 'tk',
      accessExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      idleExpiresAt: new Date(Date.now() + 25 * 60_000).toISOString(),
      user: { id: '1', email: 'u@x', name: 'U', roles: ['usuario'], perfil: 'usuario', rol: 'Consulta' },
    })

    const err = new AxiosError('forbidden')
    ;(err as { response?: unknown }).response = { status: 403, data: {} }
    vi.spyOn(api, 'get').mockRejectedValueOnce(err)

    await expect(api.get('/protected')).rejects.toBeTruthy()

    expect(auth.isAuthenticated).toBe(true)
    expect(auth.accessToken).toBe('tk')

    await t.flush()
  })
})
```

## Adapt

- If your interceptor uses `router.push('/forbidden')` on 403, add an assertion via `vi.mock('vue-router')` that verifies the push happened once.
- If the project differentiates 403 types (e.g. "role missing" vs "feature-flagged off"), add one test per branch.
- If your auth layer does NOT have a refresh coordinator, remove the first test and only keep the "no session wipe" one.
