# Pattern 05 — Refresh Coordinator · 401 Cascade Protection

**Covers:** `R32` · **OWASP:** A07 · **Severity:** blocker

Centralised gatekeeper for token refresh. Four guarantees:

1. **Single-flight** — concurrent 401s share one `inFlight` refresh promise.
2. **Cooldown** — a successful refresh is cached for ~5s.
3. **Max attempts** — bounded retry budget (`MAX_REFRESH_ATTEMPTS = 3`).
4. **Reset on logout** — `resetRefreshCoordinator()` wipes `inFlight` + `lastResult`.

Each test logs the cascade scenario in `Input -` and the actual call counts to the spied refresh adapter in `Output -`, so a regression in the single-flight or cooldown logic is immediately visible.

## Example spec — `tests/security/refresh-coordinator.security-html.spec.ts`

```typescript
/**
 * Refresh Coordinator - 401 cascade protection
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
        'against the backend.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    t.step('Prepare: spy on the refresh adapter')
    const refresh = vi.fn().mockResolvedValue(okResult)
    setRefreshAdapter({ refresh })
    t.evidence('Input - attacker pattern simulated', {
      scenario: 'three concurrent 401s from different axios requests',
      okResult,
    })

    t.step('Execute: fire 3 parallel refreshAccessToken() calls')
    const [a, b, c] = await Promise.all([
      refreshAccessToken(),
      refreshAccessToken(),
      refreshAccessToken(),
    ])

    t.step('Verify: one backend call, single shared promise')
    expect(a).toBe(b)
    expect(b).toBe(c)
    expect(refresh).toHaveBeenCalledTimes(1)

    t.evidence('Output - defense result', {
      adapterCalls: refresh.mock.calls.length,
      sharedPromise: a === b && b === c,
      backendSaved: 2,
    })

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
        'coordinator does NOT fire 50 refreshes - it reuses the recent ' +
        'result for 5s and lets the interceptor fail cleanly.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    const refresh = vi.fn().mockResolvedValue(okResult)
    setRefreshAdapter({ refresh })

    t.step('Prepare: prime the cache with one refresh')
    await refreshAccessToken()
    t.evidence('Input - cascade scenario simulated', {
      warmups: 1,
      subsequentCalls: 2,
      cooldownMs: 5_000,
    })

    t.step('Execute: two immediate follow-up refreshAccessToken() calls')
    await refreshAccessToken()
    await refreshAccessToken()

    t.step('Verify: only the first call hit the backend')
    expect(refresh).toHaveBeenCalledTimes(1)

    t.evidence('Output - defense result', {
      adapterCalls: refresh.mock.calls.length,
      reusedFromCooldown: 2,
    })

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
        "Otherwise an immediate re-login could reuse the previous user's " +
        'token (cross-session token reuse).</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    const refresh = vi.fn().mockResolvedValue(okResult)
    setRefreshAdapter({ refresh })

    t.step('Prepare: one pre-logout refresh (cache populated)')
    await refreshAccessToken()
    const beforeReset = refresh.mock.calls.length

    t.step('Execute: reset + one more refresh (simulates re-login)')
    resetRefreshCoordinator()
    await refreshAccessToken()
    const afterReset = refresh.mock.calls.length

    t.step(
      'Verify: the adapter was invoked twice (reset bypassed the cooldown)',
    )
    expect(afterReset).toBe(2)

    t.evidence('Input - sequence', {
      order: ['refresh', 'resetRefreshCoordinator', 'refresh'],
    })
    t.evidence('Output - defense result', {
      callsBeforeReset: beforeReset,
      callsAfterReset: afterReset,
      crossSessionReuseBlocked: afterReset === 2,
    })

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
        'client into a refresh loop.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    const refresh = vi.fn().mockRejectedValue(new Error('boom'))
    setRefreshAdapter({ refresh })
    t.evidence('Input - failing backend', {
      adapterMockedTo: 'reject with Error("boom") every call',
      expectedMaxAttempts: MAX_REFRESH_ATTEMPTS,
    })

    t.step('Execute: call refreshAccessToken() and expect rejection')
    await expect(refreshAccessToken()).rejects.toThrow()

    t.step('Verify: the adapter was invoked exactly MAX_REFRESH_ATTEMPTS times')
    expect(refresh).toHaveBeenCalledTimes(MAX_REFRESH_ATTEMPTS)

    t.evidence('Output - defense result', {
      adapterCalls: refresh.mock.calls.length,
      capEnforced: refresh.mock.calls.length === MAX_REFRESH_ATTEMPTS,
      loopPrevented: true,
    })

    await t.flush()
  }, 10_000)
})
```

## Adapt to your project

- Replace `@/lib/api/refresh-coordinator` + `@/lib/api/refresh-adapter` with actual paths.
- If the project does not use an adapter pattern, mock `axios.post('/auth/refresh', ...)` directly.
- Adjust `okResult` shape to match the real refresh response.
- Tune `MAX_REFRESH_ATTEMPTS` and cooldown window to match your constants.
