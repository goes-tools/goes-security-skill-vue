# Pattern 05 — Refresh Coordinator · 401 Cascade Protection

**Covers:** `R32` · **OWASP:** A07 · **Severity:** blocker

Centralised gatekeeper for token refresh. Three guarantees:

1. **Single-flight** — concurrent 401s share one `inFlight` refresh promise (no stampede).
2. **Cooldown** — a successful refresh is cached for ~5s so the next 401 does NOT trigger another round-trip.
3. **Max attempts** — bounded retry budget (`MAX_REFRESH_ATTEMPTS = 3`) so a crashing backend does not drag the client into a refresh loop.
4. **`resetRefreshCoordinator()`** — wipes `inFlight` + `lastResult` on logout, preventing cross-session token reuse.

## Example spec — `tests/security/refresh-coordinator.security-html.spec.ts`

```typescript
/**
 * Refresh Coordinator — 401 cascade protection
 * ─────────────────────────────────────────────
 * Centralised gatekeeper for token refresh. Three guarantees we
 * want pinned down:
 *
 *   · Concurrent 401s share a single refresh promise (no stampede).
 *   · A successful refresh is cached for 5 s (cooldown) so the
 *     next 401 does NOT trigger another network round-trip.
 *   · `resetRefreshCoordinator()` wipes `inFlight` + `lastResult`
 *     so a logout + immediate login does not reuse a stale token.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { report } from '@security-reporter/metadata'
import {
  MAX_REFRESH_ATTEMPTS,
  refreshAccessToken,
  resetRefreshCoordinator,
} from '@/lib/api/refresh-coordinator'
import {
  setRefreshAdapter,
  type RefreshResult,
} from '@/lib/api/refresh-adapter'

const okResult: RefreshResult = {
  accessToken: 'new-token',
  accessExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
  idleExpiresAt: new Date(Date.now() + 25 * 60_000).toISOString(),
}

describe('[GOES Security FE] refresh-coordinator', () => {
  beforeEach(() => {
    resetRefreshCoordinator()
  })

  it('[R32] concurrent calls share one inFlight refresh (no stampede)', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Refresh coordinator')
    t.story('Concurrent 401s share one refresh')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R32')
    t.descriptionHtml(
      '<p>If two requests fail 401 simultaneously the coordinator must ' +
        'fire a single POST /auth/refresh and share the promise with ' +
        'both callers, not two parallel refreshes. Prevents stampede ' +
        'against the backend.</p>',
    )

    const refresh = vi.fn().mockResolvedValue(okResult)
    setRefreshAdapter({ refresh })

    const [a, b, c] = await Promise.all([
      refreshAccessToken(),
      refreshAccessToken(),
      refreshAccessToken(),
    ])

    expect(a).toBe(b)
    expect(b).toBe(c)
    expect(refresh).toHaveBeenCalledTimes(1)

    await t.flush()
  })

  it('[R32] cooldown reuses last result within 5s window', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Refresh coordinator')
    t.story('Cooldown prevents 401 cascades')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R32')
    t.descriptionHtml(
      '<p>After a successful refresh, if 50 requests cascade into 401s ' +
        '(e.g. the user agent has a bug and rejects the new token), the ' +
        'coordinator does NOT fire 50 refreshes — it reuses the recent ' +
        'result for 5 s and lets the interceptor fail cleanly.</p>',
    )

    const refresh = vi.fn().mockResolvedValue(okResult)
    setRefreshAdapter({ refresh })

    await refreshAccessToken() // primes the cache
    await refreshAccessToken() // should reuse
    await refreshAccessToken() // should reuse

    expect(refresh).toHaveBeenCalledTimes(1)

    await t.flush()
  })

  it('[R32] resetRefreshCoordinator clears inFlight + lastResult', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Refresh coordinator')
    t.story('Reset wipes cache on logout')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R32')
    t.descriptionHtml(
      '<p>When the user logs out the coordinator cache must be cleared. ' +
        'Otherwise an immediate re-login could reuse the previous ' +
        "user's token (cross-session token reuse).</p>",
    )

    const refresh = vi.fn().mockResolvedValue(okResult)
    setRefreshAdapter({ refresh })

    await refreshAccessToken()
    resetRefreshCoordinator()
    await refreshAccessToken()

    expect(refresh).toHaveBeenCalledTimes(2)

    await t.flush()
  })

  it('[R32] caps retries at MAX_REFRESH_ATTEMPTS', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Refresh coordinator')
    t.story('Retry budget prevents backend hammering')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R32')
    t.descriptionHtml(
      '<p>If the backend errors on refresh, the coordinator retries up ' +
        'to <strong>MAX_REFRESH_ATTEMPTS=3</strong> times and then ' +
        'gives up. Without this cap a failing backend would drag the ' +
        'client into a refresh loop.</p>',
    )

    const refresh = vi.fn().mockRejectedValue(new Error('boom'))
    setRefreshAdapter({ refresh })

    await expect(refreshAccessToken()).rejects.toThrow()
    expect(refresh).toHaveBeenCalledTimes(MAX_REFRESH_ATTEMPTS)

    await t.flush()
  }, 10_000)
})
```

## Adapt

- Replace `@/lib/api/refresh-coordinator` + `@/lib/api/refresh-adapter` with actual paths.
- If the project does not use an adapter pattern, mock `axios.post('/auth/refresh', ...)` directly.
- Adjust `okResult` shape to match the real refresh response.
- Tune `MAX_REFRESH_ATTEMPTS` and cooldown window to match your constants.
