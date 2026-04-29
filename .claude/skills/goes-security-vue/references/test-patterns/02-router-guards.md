# Pattern 02 — Vue Router Guards · Auth + RBAC + Hydration

**Covers:** `R9`, `R21`, `R24`, `VF8` · **OWASP:** A01 · **Severity:** blocker / critical

Three behaviours the audit relies on:

1. `meta.requiresAuth: true` without session → redirect to `/login` with `?redirect=<original-path>`.
2. `meta.guestOnly: true` with active session → bounce away from `/login` to the dashboard.
3. `meta.roles: [...]` + user lacks the role → redirect to `/forbidden` (never to `/login` — that would falsely suggest re-logging fixes the problem).
4. Role requirements are read from ANY level of the matched route chain (parent or child).

Every guard decision is captured in `Output - guard decision` evidence, so a regression on parent-route inheritance is immediately visible in the HTML report.

## Example spec — `tests/security/router-guards.security-html.spec.ts`

```typescript
/**
 * Router guards - auth + RBAC + hydration
 * ────────────────────────────────────────
 * Pin down the three behaviours the audit relies on:
 *
 *   · `requiresAuth` without session → redirect to /login with
 *     the original path preserved in `?redirect=`.
 *   · `guestOnly` with session → bounce away from /login into
 *     the dashboard (avoid confusing returning users).
 *   · `roles: [...]` + user lacks the role → redirect to
 *     /forbidden (not to /login).
 *   · Role requirements are picked up from ANY level of the
 *     matched route chain (parent or child).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { report } from '@security-reporter/metadata'

vi.mock('@/lib/api/session-scheduler', () => ({
  scheduleSessionTimers: vi.fn(),
  cancelSessionTimers: vi.fn(),
}))
vi.mock('@/lib/api/refresh-coordinator', () => ({
  resetRefreshCoordinator: vi.fn(),
}))
vi.mock('@/lib/api/activity-tracker', () => ({
  markActivity: vi.fn(),
  startActivityTracking: vi.fn(),
  stopActivityTracking: vi.fn(),
}))
vi.mock('@/features/auth/services/auth.service', () => ({
  authService: {
    hydrateFromRefreshCookie: vi.fn().mockResolvedValue(null),
  },
}))

import { authGuard } from '@/router/guards'
import { useAuthStore } from '@/features/auth/stores/auth.store'
import type { AuthSession } from '@/features/auth/types'
import type { NavigationGuardReturn, RouteLocationNormalized } from 'vue-router'

function route(
  path: string,
  meta: RouteLocationNormalized['meta'] = {},
  matched: RouteLocationNormalized['matched'] = [],
): RouteLocationNormalized {
  return {
    path,
    fullPath: path,
    name: undefined,
    hash: '',
    query: {},
    params: {},
    matched:
      matched.length > 0
        ? matched
        : [{ meta } as unknown as RouteLocationNormalized['matched'][number]],
    meta,
    redirectedFrom: undefined,
  }
}

function session(): AuthSession {
  return {
    accessToken: 'tk',
    accessExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    idleExpiresAt: new Date(Date.now() + 25 * 60_000).toISOString(),
    user: {
      id: '1',
      email: 'user@goes.gob.sv',
      name: 'User',
      roles: ['usuario'],
      perfil: 'usuario',
      rol: 'Consulta',
    },
  }
}

async function runGuard(to: RouteLocationNormalized) {
  const from = route('/login')
  const result = await (
    authGuard as unknown as (
      to: RouteLocationNormalized,
      from: RouteLocationNormalized,
      next: unknown,
    ) => Promise<NavigationGuardReturn>
  )(to, from, undefined as never)
  return result
}

describe('[GOES Security FE] router/guards', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('[R9] requiresAuth without session redirects to /login with redirect query', async () => {
    const t = report()
    t.epic('Access Control')
    t.feature('Router guard')
    t.story('Unauthenticated visit of a private route')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
    t.descriptionHtml(
      '<p>If an unauthenticated user tries to open ' +
        '<code>/dashboard/maintainer</code> the guard must push them to ' +
        '<code>/login</code> and note the target in <code>?redirect=</code> ' +
        'so they come back after authenticating.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    t.step('Prepare: no session, navigate to /dashboard/maintainer')
    const to = route('/dashboard/maintainer', { requiresAuth: true })
    t.evidence('Input - navigation attempt', {
      path: to.path,
      meta: to.meta,
      storeState: 'no session',
    })

    t.step('Execute: run the guard')
    const result = await runGuard(to)

    t.step('Verify: redirect to login with ?redirect= preserving the target')
    expect(result).toMatchObject({
      name: 'login',
      query: { redirect: '/dashboard/maintainer' },
    })

    t.evidence('Output - guard decision', {
      redirect: result,
      preservedRedirectQuery: '/dashboard/maintainer',
    })

    await t.flush()
  })

  it('[R9] guestOnly with active session bounces to the dashboard', async () => {
    const t = report()
    t.epic('Access Control')
    t.feature('Router guard')
    t.story('Logged-in user cannot re-enter /login')
    t.severity('normal')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
    t.descriptionHtml(
      '<p>After a successful login the user should not see the login ' +
        'form again — bounce them into the dashboard to avoid confusion.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    t.step('Prepare: authenticated user navigates to /login')
    const auth = useAuthStore()
    auth.setSession(session())
    const to = route('/login', { guestOnly: true })
    t.evidence('Input - navigation attempt', {
      path: to.path,
      meta: to.meta,
      storeState: 'authenticated (usuario)',
    })

    t.step('Execute: run the guard')
    const result = await runGuard(to)

    t.step('Verify: guard bounces to the portfolio-category route')
    expect(result).toMatchObject({ name: 'portfolio-category' })

    t.evidence('Output - guard decision', { redirect: result })

    await t.flush()
  })

  it('[R9] role mismatch redirects to /forbidden (never to /login)', async () => {
    const t = report()
    t.epic('RBAC')
    t.feature('Router guard')
    t.story('Missing role surfaces as 403, not 401')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
    t.descriptionHtml(
      '<p>An authenticated user that lacks the required role must land ' +
        'on <code>/forbidden</code>. Sending them to <code>/login</code> ' +
        'would be confusing and give the false impression that ' +
        '"logging in again" grants the permission — which is not the case.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    t.step('Prepare: authenticated as usuario, attempting an admin route')
    const auth = useAuthStore()
    auth.setSession(session())
    const to = route('/dashboard/maintainer', {
      requiresAuth: true,
      roles: ['admin'],
    })
    t.evidence('Input - navigation attempt', {
      path: to.path,
      meta: to.meta,
      userRoles: ['usuario'],
      requiredRoles: ['admin'],
    })

    t.step('Execute: run the guard')
    const result = await runGuard(to)

    t.step('Verify: guard resolves to the forbidden route')
    expect(result).toMatchObject({ name: 'forbidden' })

    t.evidence('Output - guard decision', { redirect: result })

    await t.flush()
  })

  it('[R9] role requirement is read from ANY level of the matched chain', async () => {
    const t = report()
    t.epic('RBAC')
    t.feature('Router guard')
    t.story('Roles in parent route are honoured')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
    t.descriptionHtml(
      '<p>When the <code>roles</code> restriction lives on the parent ' +
        'route (/dashboard) and the child inherits it, the guard must ' +
        'still pick it up. A common bug is to only inspect ' +
        '<code>to.meta</code> and miss the inheritance.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    t.step(
      'Prepare: authenticated as usuario + matched chain with parent roles',
    )
    const auth = useAuthStore()
    auth.setSession(session())
    const matched = [
      { meta: { roles: ['admin'] } },
      { meta: {} },
    ] as unknown as RouteLocationNormalized['matched']

    const to = route('/dashboard/anything', { requiresAuth: true }, matched)
    t.evidence('Input - route chain', {
      path: to.path,
      childMeta: to.meta,
      parentChain: matched.map((r) => (r as { meta: unknown }).meta),
      userRoles: ['usuario'],
    })

    t.step('Execute: run the guard')
    const result = await runGuard(to)

    t.step('Verify: guard reads the parent roles and redirects to forbidden')
    expect(result).toMatchObject({ name: 'forbidden' })

    t.evidence('Output - guard decision', {
      redirect: result,
      parentRoleInheritanceWorks: true,
    })

    await t.flush()
  })
})
```

## Adapt to your project

- Replace `authGuard` import path with your router's guard location (`@/router/guards` or similar).
- Adjust `useAuthStore` import.
- Add / remove `setSession` mocks depending on which side-effects your auth layer triggers (scheduler, activity tracker, refresh coordinator).
- Route names (`portfolio-category`, `forbidden`, `login`) must match your router definitions.
