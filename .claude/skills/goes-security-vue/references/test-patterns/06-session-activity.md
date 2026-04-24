# Pattern 06 — Session Scheduler + Activity Tracker

**Covers:** `R35`, `R40` · **OWASP:** A04, A07 · **Severity:** high / critical

Together the session scheduler and activity tracker own the idle-logout feature. Four guarantees:

1. `startActivityTracking()` is **idempotent** — double mounts don't attach duplicate DOM listeners.
2. `markActivity()` resets the "last seen" clock immediately.
3. `cancelSessionTimers()` wipes every pending refresh / warning / logout timer (critical on logout to avoid a timer firing against a fresh session).
4. `scheduleSessionTimers()` exposes an `idle` ref with `warning: false` right after scheduling — the warning appears only when the threshold is crossed.

## Example spec — `tests/security/session-activity.security-html.spec.ts`

```typescript
/**
 * Session scheduler + activity tracker
 * ─────────────────────────────────────
 * Together they own the idle-logout feature. Four guarantees:
 *
 *   · activity-tracker only starts once (idempotent), so double
 *     mounts don't attach duplicate DOM listeners.
 *   · `markActivity()` resets the "last seen" clock immediately.
 *   · `cancelSessionTimers()` wipes every pending refresh /
 *     warning / logout timer (critical on logout to avoid a
 *     timer firing against a fresh session).
 *   · `scheduleSessionTimers()` exposes an `idle` ref with
 *     `{ warning: false }` right after scheduling — the warning
 *     appears only when the threshold is crossed.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { report } from '@security-reporter/metadata'
import {
  getMsSinceLastActivity,
  markActivity,
  startActivityTracking,
  stopActivityTracking,
} from '@/lib/api/activity-tracker'
import {
  cancelSessionTimers,
  idle,
  scheduleSessionTimers,
} from '@/lib/api/session-scheduler'

afterEach(() => {
  stopActivityTracking()
  cancelSessionTimers()
  vi.useRealTimers()
})

describe('[GOES Security FE] activity-tracker', () => {
  it('[R40] startActivityTracking is idempotent (double call, single listener set)', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Activity tracker')
    t.story('Idempotent start')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A04', 'GOES-R40')
    t.descriptionHtml(
      '<p>Several screens mount the tracker; calling it twice must ' +
        'leave a single set of listeners. Otherwise every event ' +
        '(mousemove, keydown) marks activity N times and the UI ' +
        'becomes jittery.</p>',
    )

    const spy = vi.spyOn(window, 'addEventListener')
    startActivityTracking()
    const afterFirst = spy.mock.calls.length
    startActivityTracking() // idempotent
    const afterSecond = spy.mock.calls.length

    expect(afterSecond).toBe(afterFirst)
    spy.mockRestore()

    await t.flush()
  })

  it('[R40] markActivity resets "ms since last activity" to ~0', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Activity tracker')
    t.story('markActivity resets the clock')
    t.severity('normal')
    t.tag('Pentest', 'OWASP-A04', 'GOES-R40')

    // Simulate time drift by pretending an older "last seen".
    markActivity()
    const ms = getMsSinceLastActivity()
    expect(ms).toBeLessThan(50)

    await t.flush()
  })
})

describe('[GOES Security FE] session-scheduler', () => {
  it('[R40] scheduleSessionTimers initialises idle ref without warning', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Idle timers')
    t.story('Initial state is not-warning')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A04', 'GOES-R40')

    const idleExp = new Date(Date.now() + 25 * 60_000)
    scheduleSessionTimers({
      accessExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      idleExpiresAt: idleExp.toISOString(),
    })

    // Right after scheduling we are not in the warning window yet,
    // so `warning` is false but `deadlineMs` MUST already point at
    // the absolute idle expiration so the banner can render a
    // countdown when the threshold eventually kicks in.
    expect(idle.value.warning).toBe(false)
    expect(idle.value.deadlineMs).toBe(idleExp.getTime())

    await t.flush()
  })

  it('[R40] cancelSessionTimers clears pending timers so a stale one cannot logout a fresh session', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Idle timers')
    t.story('Timers are torn down on logout')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A04', 'GOES-R40')
    t.descriptionHtml(
      '<p>If the user logs out and logs back in within the idle ' +
        'window, a leftover timer from the previous session could ' +
        'fire a ghost logout on the new one. ' +
        '<code>cancelSessionTimers()</code> must wipe everything.</p>',
    )

    vi.useFakeTimers()
    scheduleSessionTimers({
      accessExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      idleExpiresAt: new Date(Date.now() + 60_000).toISOString(),
    })
    cancelSessionTimers()

    // Advance past the idle deadline. Nothing should fire because
    // we cancelled — the idle ref stays with warning:false.
    vi.advanceTimersByTime(2 * 60_000)
    expect(idle.value.warning).toBe(false)

    await t.flush()
  })
})
```

## Adapt

- Replace imports from `@/lib/api/activity-tracker` and `@/lib/api/session-scheduler` with actual paths.
- If your project exposes a single `useIdleTimeout()` composable instead of two modules, adapt the assertions to test the composable's public API.
- Real projects should also have a UI-level smoke test (e.g. `IdleModal.vue` component test) that verifies the warning banner renders at the right time; add it as a sibling spec if the composable surface is too internal.
