# Pattern 06 — Session Scheduler + Activity Tracker

**Covers:** `R35`, `R40` · **OWASP:** A04, A07 · **Severity:** high / critical

The session scheduler and activity tracker own the idle-logout feature. Four guarantees:

1. `startActivityTracking()` is idempotent.
2. `markActivity()` resets the "last seen" clock immediately.
3. `cancelSessionTimers()` wipes every pending timer (critical on logout).
4. `scheduleSessionTimers()` exposes an `idle` ref correctly.

Listener counts and timer state are captured as evidence in every test.

## Example spec — `tests/security/session-activity.security-html.spec.ts`

```typescript
/**
 * Session scheduler + activity tracker
 * ─────────────────────────────────────
 * Together they own the idle-logout feature. Four guarantees:
 *
 *   · activity-tracker only starts once (idempotent).
 *   · `markActivity()` resets the "last seen" clock immediately.
 *   · `cancelSessionTimers()` wipes every pending refresh /
 *     warning / logout timer.
 *   · `scheduleSessionTimers()` exposes an `idle` ref with
 *     `{ warning: false }` right after scheduling.
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
        '(mousemove, keydown) marks activity N times.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A04_2021-Insecure_Design/" target="_blank" rel="noopener">OWASP A04</a>.</p>',
    )

    t.step('Prepare: spy on window.addEventListener BEFORE starting')
    const spy = vi.spyOn(window, 'addEventListener')
    const baseline = spy.mock.calls.length

    t.step('Execute: startActivityTracking() twice')
    startActivityTracking()
    const afterFirst = spy.mock.calls.length
    startActivityTracking()
    const afterSecond = spy.mock.calls.length

    t.step('Verify: second call did NOT add extra listeners')
    expect(afterSecond).toBe(afterFirst)
    spy.mockRestore()

    t.evidence('Input - startActivityTracking invocations', {
      sequence: ['baseline', 'first', 'second'],
    })
    t.evidence('Output - addEventListener call counts', {
      baseline,
      afterFirst,
      afterSecond,
      delta: afterSecond - afterFirst,
    })

    await t.flush()
  })

  it('[R40] markActivity resets "ms since last activity" to ~0', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Activity tracker')
    t.story('markActivity resets the clock')
    t.severity('normal')
    t.tag('Pentest', 'OWASP-A04', 'GOES-R40')
    t.descriptionHtml(
      '<p>Marking activity must bring the idle timer back to zero — ' +
        'a ~50 ms tolerance accommodates scheduler jitter.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A04_2021-Insecure_Design/" target="_blank" rel="noopener">OWASP A04</a>.</p>',
    )

    t.step('Execute: markActivity() then read getMsSinceLastActivity()')
    markActivity()
    const ms = getMsSinceLastActivity()

    t.step('Verify: elapsed is < 50ms')
    expect(ms).toBeLessThan(50)

    t.evidence('Input - trigger', { action: 'markActivity()' })
    t.evidence('Output - observed delay', {
      msSinceLastActivity: ms,
      toleranceMs: 50,
    })

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
    t.descriptionHtml(
      '<p>Right after scheduling we are NOT in the warning window yet, ' +
        'so <code>warning</code> is false but <code>deadlineMs</code> ' +
        'MUST already point at the absolute idle expiration so the ' +
        'banner can render a countdown when the threshold eventually ' +
        'kicks in.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A04_2021-Insecure_Design/" target="_blank" rel="noopener">OWASP A04</a>.</p>',
    )

    t.step('Prepare: compute access + idle deadlines 15 / 25 min in the future')
    const idleExp = new Date(Date.now() + 25 * 60_000)
    const input = {
      accessExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      idleExpiresAt: idleExp.toISOString(),
    }
    t.evidence('Input - scheduleSessionTimers args', input)

    t.step('Execute: scheduleSessionTimers(input)')
    scheduleSessionTimers(input)

    t.step('Verify: idle.warning=false, deadlineMs=idleExp.getTime()')
    expect(idle.value.warning).toBe(false)
    expect(idle.value.deadlineMs).toBe(idleExp.getTime())

    t.evidence('Output - idle ref snapshot', {
      warning: idle.value.warning,
      deadlineMs: idle.value.deadlineMs,
      expectedDeadlineMs: idleExp.getTime(),
    })

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
      '<p>If the user logs out and logs back in within the idle window, ' +
        'a leftover timer from the previous session could fire a ghost ' +
        'logout on the new one. <code>cancelSessionTimers()</code> must ' +
        'wipe everything.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A04_2021-Insecure_Design/" target="_blank" rel="noopener">OWASP A04</a>.</p>',
    )

    t.step('Prepare: fake timers + schedule a 60s idle window')
    vi.useFakeTimers()
    scheduleSessionTimers({
      accessExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      idleExpiresAt: new Date(Date.now() + 60_000).toISOString(),
    })
    t.evidence('Input - stale timer setup', {
      idleWindowMs: 60_000,
      accessWindowMs: 15 * 60_000,
    })

    t.step('Execute: cancelSessionTimers() then advance 2 minutes')
    cancelSessionTimers()
    vi.advanceTimersByTime(2 * 60_000)

    t.step('Verify: idle.warning stayed false (nothing fired)')
    expect(idle.value.warning).toBe(false)

    t.evidence('Output - post-cancel state after 2 minutes', {
      warning: idle.value.warning,
      ghostLogoutFired: idle.value.warning,
    })

    await t.flush()
  })
})
```

## Adapt to your project

- Replace imports from `@/lib/api/activity-tracker` and `@/lib/api/session-scheduler` with actual paths.
- If your project exposes a single `useIdleTimeout()` composable instead of two modules, adapt the assertions to test the composable's public API.
- Real projects should also have a UI-level smoke test that verifies the warning banner renders at the right time.
