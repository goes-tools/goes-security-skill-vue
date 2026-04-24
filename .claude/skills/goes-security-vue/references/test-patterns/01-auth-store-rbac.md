# Pattern 01 — Auth Store · Session Invariants

**Covers:** `R9`, `R34`, `VF7` · **OWASP:** A01 · **Severity:** blocker

The Pinia auth store is the client-side identity surface. Three invariants protect users after logout and block privilege escalation:

1. `clearSession()` wipes ALL auth state (token, user, roles, expiration timestamps).
2. `hasRole()` / `hasAnyRole()` use **strict equality** — no prefix / case-insensitive matches.
3. `can()` derives from the **PERMISOS map** (administrador / tecnico / usuario), never from a free-form role string. Unknown perfiles fall back to `usuario` (fail-closed).

## Example spec — `tests/security/auth-store.security-html.spec.ts`

```typescript
/**
 * Auth Store — session invariants
 * ────────────────────────────────
 * The store is the client-side identity surface. These tests pin
 * down the three behaviours that break if tampered with:
 *
 *   · clearSession() wipes ALL auth state (token, user, roles,
 *     permissions) so no residue remains post-logout.
 *   · hasRole / hasAnyRole enforces exact-match RBAC (no prefix
 *     / case-insensitive matches sneaking in).
 *   · can() derives from the PERMISOS matrix (administrador /
 *     tecnico / usuario) — never from the role string directly.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { report } from '@security-reporter/metadata'
import { useAuthStore } from '@/features/auth/stores/auth.store'
import type { AuthSession, AuthUser } from '@/features/auth/types'

// Every test drops into a fresh Pinia so state does not leak.
beforeEach(() => {
  setActivePinia(createPinia())
})

// The scheduler + activity tracker are wired into setSession as
// global side-effects; stub them so we're testing state only.
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

function user(overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    id: '1',
    email: 'admin@goes.gob.sv',
    name: 'Admin',
    roles: ['admin'],
    perfil: 'administrador',
    rol: 'Administrador',
    ...overrides,
  }
}

function session(overrides: Partial<AuthSession> = {}): AuthSession {
  return {
    accessToken: 'tk-123',
    accessExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    idleExpiresAt: new Date(Date.now() + 25 * 60_000).toISOString(),
    user: user(),
    ...overrides,
  }
}

describe('[GOES Security FE] auth.store', () => {
  it('[R9] clearSession wipes accessToken, user, roles and timestamps', async () => {
    const t = report()
    t.epic('Session Management')
    t.feature('Logout hygiene')
    t.story('clearSession wipes ALL auth state')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A07', 'GOES-R9')
    t.descriptionHtml(
      '<p>A logout must leave the store identical to its initial ' +
        'state. If anything survives (in-memory token, user, roles, ' +
        'expiration timestamps), a component mounted after logout ' +
        'could render data from the previous user.</p>',
    )

    const auth = useAuthStore()
    auth.setSession(session())
    expect(auth.isAuthenticated).toBe(true)

    auth.clearSession()

    expect(auth.isAuthenticated).toBe(false)
    expect(auth.accessToken).toBeNull()
    expect(auth.user).toBeNull()
    expect(auth.roles).toEqual([])
    expect(auth.accessExpiresAt).toBeNull()
    expect(auth.idleExpiresAt).toBeNull()

    await t.flush()
  })

  it('[R9] hasRole requires exact match (no prefix, no case-insensitive)', async () => {
    const t = report()
    t.epic('RBAC')
    t.feature('Role matching')
    t.story('Exact match only')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
    t.descriptionHtml(
      '<p>If <code>hasRole("admin")</code> also matched "Admin" or ' +
        '"admins" an attacker could elevate privileges by writing the ' +
        'role with a different capitalisation into the JWT. The guard ' +
        'must use strict equality.</p>',
    )

    const auth = useAuthStore()
    auth.setSession(session({ user: user({ roles: ['admin'] }) }))

    expect(auth.hasRole('admin')).toBe(true)
    // @ts-expect-error — we pass strings that are NOT in the Role type on purpose.
    expect(auth.hasRole('Admin')).toBe(false)
    // @ts-expect-error
    expect(auth.hasRole('ADMIN')).toBe(false)
    // @ts-expect-error
    expect(auth.hasRole('admins')).toBe(false)
    expect(auth.hasRole('usuario')).toBe(false)

    await t.flush()
  })

  it('[R9] hasAnyRole returns false on empty intersection', async () => {
    const t = report()
    t.epic('RBAC')
    t.feature('Role matching')
    t.story('hasAnyRole strict intersection')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')

    const auth = useAuthStore()
    auth.setSession(session({ user: user({ roles: ['usuario'] }) }))

    expect(auth.hasAnyRole(['admin', 'tecnico'])).toBe(false)
    expect(auth.hasAnyRole(['usuario', 'admin'])).toBe(true)
    // Empty required list is treated as "public" — documented behaviour.
    expect(auth.hasAnyRole([])).toBe(true)

    await t.flush()
  })

  it('[R9] can() derives from PERMISOS matrix, not from role string', async () => {
    const t = report()
    t.epic('RBAC')
    t.feature('Permissions matrix')
    t.story('can() uses PERMISOS by perfil')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
    t.descriptionHtml(
      '<p>The source of truth is the PERMISOS matrix indexed by ' +
        '<code>perfil</code> (administrador / tecnico / usuario), not ' +
        'the free-form <code>rol</code> string. This way a backend ' +
        'that introduces a new experimental role does not grant ' +
        'capabilities until we also extend the map.</p>',
    )

    const auth = useAuthStore()

    auth.setSession(session({ user: user({ perfil: 'administrador' }) }))
    expect(auth.can('eliminar')).toBe(true)
    expect(auth.can('verMantenedor')).toBe(true)

    auth.setSession(session({ user: user({ perfil: 'tecnico' }) }))
    expect(auth.can('eliminar')).toBe(false)
    expect(auth.can('verMantenedor')).toBe(false)
    expect(auth.can('editar')).toBe(true)

    auth.setSession(session({ user: user({ perfil: 'usuario' }) }))
    expect(auth.can('eliminar')).toBe(false)
    expect(auth.can('editar')).toBe(false)
    expect(auth.can('agregar')).toBe(false)
    expect(auth.can('verMantenedor')).toBe(false)

    await t.flush()
  })

  it('[R9] unknown perfil falls back to `usuario` permissions (fail-closed)', async () => {
    const t = report()
    t.epic('RBAC')
    t.feature('Permissions matrix')
    t.story('Unknown perfil denies privileged actions')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
    t.descriptionHtml(
      '<p>If the backend returns a perfil the FE does not know about ' +
        '(version mismatch, typo) the default must be the least ' +
        'privileged one. Never fail-open.</p>',
    )

    const auth = useAuthStore()
    auth.setSession(session({ user: user({ perfil: 'supervisor' }) }))

    expect(auth.can('eliminar')).toBe(false)
    expect(auth.can('agregar')).toBe(false)
    expect(auth.can('editar')).toBe(false)
    expect(auth.can('verMantenedor')).toBe(false)

    await t.flush()
  })
})
```

## Adapt to your project

- Replace `@/features/auth/stores/auth.store` with the real import.
- If the store uses Vuex, replace `useAuthStore()` with the Vuex equivalent and adjust setters.
- The `PERMISOS` map lives in `@/features/auth/types`. If your project uses a different permissions model (ACL list, single `role` string), adapt the `can()` assertions accordingly.
- Add tests for every `perfil` × `flag` combination used in your app (admin gets everything, técnico gets a subset, usuario is read-only).
