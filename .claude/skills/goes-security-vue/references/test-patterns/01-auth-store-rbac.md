# Pattern 01 — Auth Store · Session Invariants

**Covers:** `R9`, `R34`, `VF7` · **OWASP:** A01 · **Severity:** blocker

The Pinia auth store is the client-side identity surface. Three invariants protect users after logout and block privilege escalation:

1. `clearSession()` wipes ALL auth state (token, user, roles, expiration timestamps).
2. `hasRole()` / `hasAnyRole()` use **strict equality** — no prefix / case-insensitive matches.
3. `can()` derives from the **PERMISOS map** (administrador / tecnico / usuario), never from a free-form role string. Unknown perfiles fall back to `usuario` (fail-closed).

Each test ships `t.evidence('… (input)')` (the attacker tampering attempt) and `t.evidence('… (output)')` (the store state after the action) so the HTML report shows exactly what was tried and how the defence reacted.

## Example spec — `tests/security/auth-store.security-html.spec.ts`

```typescript
/**
 * Auth Store - session invariants
 * ────────────────────────────────
 * The store is the client-side identity surface. These tests pin
 * down the three behaviours that break if tampered with:
 *
 *   · clearSession() wipes ALL auth state (token, user, roles,
 *     permissions) so no residue remains post-logout.
 *   · hasRole / hasAnyRole enforces exact-match RBAC (no prefix
 *     / case-insensitive matches sneaking in).
 *   · can() derives from the PERMISOS matrix (administrador /
 *     tecnico / usuario) - never from the role string directly.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { report } from '@security-reporter/metadata'
import { useAuthStore } from '@/features/auth/stores/auth.store'
import type { AuthSession, AuthUser } from '@/features/auth/types'

beforeEach(() => {
  setActivePinia(createPinia())
})

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
      '<p>A logout must leave the store identical to its initial state. ' +
        'If anything survives (in-memory token, user, roles, expiration ' +
        'timestamps), a component mounted after logout could render data ' +
        'from the previous user.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="_blank" rel="noopener">OWASP A07</a>.</p>',
    )

    t.step('Prepare: populate the store with a fully authenticated session')
    const auth = useAuthStore()
    const authenticated = session()
    auth.setSession(authenticated)
    t.evidence('session before logout (input)', {
      accessToken: authenticated.accessToken,
      user: authenticated.user,
      accessExpiresAt: authenticated.accessExpiresAt,
      idleExpiresAt: authenticated.idleExpiresAt,
      isAuthenticated: auth.isAuthenticated,
    })
    expect(auth.isAuthenticated).toBe(true)

    t.step('Execute: call auth.clearSession()')
    auth.clearSession()

    t.step('Verify: every sensitive slot is back to its initial value')
    expect(auth.isAuthenticated).toBe(false)
    expect(auth.accessToken).toBeNull()
    expect(auth.user).toBeNull()
    expect(auth.roles).toEqual([])
    expect(auth.accessExpiresAt).toBeNull()
    expect(auth.idleExpiresAt).toBeNull()

    t.evidence('store snapshot after clearSession (output)', {
      accessToken: auth.accessToken,
      user: auth.user,
      roles: auth.roles,
      accessExpiresAt: auth.accessExpiresAt,
      idleExpiresAt: auth.idleExpiresAt,
      isAuthenticated: auth.isAuthenticated,
    })

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
        'must use strict equality.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    t.step('Prepare: authenticate as admin (roles: ["admin"])')
    const auth = useAuthStore()
    auth.setSession(session({ user: user({ roles: ['admin'] }) }))
    t.evidence('attacker role-tampering candidates (input)', {
      legitimate: 'admin',
      payloads: ['Admin', 'ADMIN', 'admins', 'usuario'],
    })

    t.step('Execute + Verify: each tampered variant must NOT satisfy hasRole()')
    expect(auth.hasRole('admin')).toBe(true)
    // @ts-expect-error - wrong-case role, not in the Role union.
    expect(auth.hasRole('Admin')).toBe(false)
    // @ts-expect-error - uppercase role, not in the Role union.
    expect(auth.hasRole('ADMIN')).toBe(false)
    // @ts-expect-error - plural form, not in the Role union.
    expect(auth.hasRole('admins')).toBe(false)
    expect(auth.hasRole('usuario')).toBe(false)

    t.evidence('hasRole decisions per payload (output)', {
      admin: auth.hasRole('admin'),
      // @ts-expect-error - intentional
      Admin: auth.hasRole('Admin'),
      // @ts-expect-error - intentional
      ADMIN: auth.hasRole('ADMIN'),
      // @ts-expect-error - intentional
      admins: auth.hasRole('admins'),
      usuario: auth.hasRole('usuario'),
    })

    await t.flush()
  })

  it('[R9] hasAnyRole returns false on empty intersection', async () => {
    const t = report()
    t.epic('RBAC')
    t.feature('Role matching')
    t.story('hasAnyRole strict intersection')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
    t.descriptionHtml(
      '<p>Intersection semantics: at least one role must match. Empty ' +
        'required list is treated as "public" by design.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    t.step('Prepare: authenticate as usuario (roles: ["usuario"])')
    const auth = useAuthStore()
    auth.setSession(session({ user: user({ roles: ['usuario'] }) }))

    t.step('Execute + Verify: 3 intersection scenarios')
    const disjoint = auth.hasAnyRole(['admin', 'tecnico'])
    const overlap = auth.hasAnyRole(['usuario', 'admin'])
    const empty = auth.hasAnyRole([])

    expect(disjoint).toBe(false)
    expect(overlap).toBe(true)
    expect(empty).toBe(true)

    t.evidence('required-role sets tested (input)', {
      userRoles: ['usuario'],
      scenarios: {
        disjoint: ['admin', 'tecnico'],
        overlap: ['usuario', 'admin'],
        empty: [],
      },
    })
    t.evidence('hasAnyRole() per scenario (output)', {
      disjoint,
      overlap,
      empty_means_public: empty,
    })

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
        'capabilities until we also extend the map.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    const auth = useAuthStore()

    t.step('Prepare/Execute/Verify: administrador has eliminar + verMantenedor')
    auth.setSession(session({ user: user({ perfil: 'administrador' }) }))
    const admin = {
      eliminar: auth.can('eliminar'),
      verMantenedor: auth.can('verMantenedor'),
    }
    expect(admin.eliminar).toBe(true)
    expect(admin.verMantenedor).toBe(true)

    t.step(
      'Prepare/Execute/Verify: tecnico can edit but NOT delete / NOT maintainer',
    )
    auth.setSession(session({ user: user({ perfil: 'tecnico' }) }))
    const tec = {
      eliminar: auth.can('eliminar'),
      verMantenedor: auth.can('verMantenedor'),
      editar: auth.can('editar'),
    }
    expect(tec.eliminar).toBe(false)
    expect(tec.verMantenedor).toBe(false)
    expect(tec.editar).toBe(true)

    t.step('Prepare/Execute/Verify: usuario is read-only across the board')
    auth.setSession(session({ user: user({ perfil: 'usuario' }) }))
    const usr = {
      eliminar: auth.can('eliminar'),
      editar: auth.can('editar'),
      agregar: auth.can('agregar'),
      verMantenedor: auth.can('verMantenedor'),
    }
    expect(usr.eliminar).toBe(false)
    expect(usr.editar).toBe(false)
    expect(usr.agregar).toBe(false)
    expect(usr.verMantenedor).toBe(false)

    t.evidence('perfiles tested (input)', {
      perfiles: ['administrador', 'tecnico', 'usuario'],
      flags: ['eliminar', 'editar', 'agregar', 'verMantenedor'],
    })
    t.evidence('permissions matrix cells derived from can() (output)', {
      administrador: admin,
      tecnico: tec,
      usuario: usr,
    })

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
        'privileged one. Never fail-open.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
    )

    t.step('Prepare: authenticate with a perfil unknown to the FE (supervisor)')
    const auth = useAuthStore()
    auth.setSession(session({ user: user({ perfil: 'supervisor' }) }))
    t.evidence('attacker payload (input)', {
      injectedPerfil: 'supervisor',
      attackerGoal: 'fail-open to admin-grade permissions',
    })

    t.step('Execute + Verify: every privileged flag must be denied')
    const decisions = {
      eliminar: auth.can('eliminar'),
      agregar: auth.can('agregar'),
      editar: auth.can('editar'),
      verMantenedor: auth.can('verMantenedor'),
    }
    expect(decisions.eliminar).toBe(false)
    expect(decisions.agregar).toBe(false)
    expect(decisions.editar).toBe(false)
    expect(decisions.verMantenedor).toBe(false)

    t.evidence('fallback permissions (must equal usuario) (output)', decisions)

    await t.flush()
  })
})
```

## Adapt to your project

- Replace `@/features/auth/stores/auth.store` with the real store import.
- If the store uses Vuex, replace `useAuthStore()` with the Vuex equivalent and adjust setters.
- The `PERMISOS` map lives in `@/features/auth/types`. If your project uses a different permissions model (ACL list, single `role` string), adapt the `can()` assertions accordingly.
- Add tests for every `perfil` × `flag` combination used in your app (admin gets everything, técnico gets a subset, usuario is read-only).
