# Pattern 14 — JWT Payload · Client-side Safety

**Covers:** `R20` · **OWASP:** A02 · **Severity:** critical

Only applicable if the SPA decodes the access-token JWT client-side (common for showing the logged-in user's name or role from the token claims). If your app only passes the token through as an opaque string, this pattern goes into the N/A spec with "SPA does not decode the JWT".

The rule is simple: the payload must contain ONLY identification + timing claims. Any PII (email, phone, full name, document number, cédula, DOB, address, account number) in the payload is a data-exposure risk — anyone who can read the bundle debug output can read the claims.

Acceptable claims on the SPA side: `sub` (user id), `iat`, `exp`, `iss`, `aud`, `role` (single word), `perfil` (single word), `name` (optional — debatable; prefer fetching via `/profile`).

## Example spec — `tests/security/jwt-payload.security-html.spec.ts`

```typescript
/**
 * JWT payload audit — client-side claims
 * ───────────────────────────────────────
 * Asserts that when the SPA decodes the access token (e.g. to
 * render the user name in the topbar), no PII ever travels in
 * the signed claims. The payload must be the bare minimum.
 */
import { describe, expect, it } from 'vitest'
import { report } from '@security-reporter/metadata'
import { authService } from '@/features/auth/services/auth.service'

// Helper — base64url decode without verifying the signature.
// Only for inspection during tests; never use in production UX.
function decodeJwtPayload(token: string): Record<string, unknown> {
  const [, payload] = token.split('.')
  const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'))
  return JSON.parse(json)
}

describe('[GOES Security FE] JWT payload · claims audit', () => {
  it('[R20] the payload contains ONLY identification + timing claims', async () => {
    const t = report()
    t.epic('JWT Payload Security')
    t.feature('Claims whitelist')
    t.story('No PII in the signed token')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A02', 'GOES-R20')
    t.descriptionHtml(
      '<p>If the SPA decodes the token client-side, every claim is ' +
        'visible to anyone with devtools. PII (email / phone / document ' +
        'number) MUST NOT be in the payload — fetch it via an ' +
        'authenticated <code>/profile</code> endpoint instead.</p>',
    )

    // Replace with how your project exposes the raw access token.
    // Here we pretend `authService.lastToken()` returns the string;
    // in a real project, pull from the Pinia store or from a
    // hard-coded fixture captured from staging.
    const token = 'eyJ...fixture...'

    const payload = decodeJwtPayload(token)
    const allowed = new Set(['sub', 'iat', 'exp', 'iss', 'aud', 'role', 'perfil', 'name', 'nbf', 'jti'])
    const forbidden = /(email|phone|telefono|cedula|dui|dob|address|direccion|password|secret|card|iban|ssn)/i

    const offendingKeys = Object.keys(payload).filter(
      (k) => forbidden.test(k) || !allowed.has(k),
    )

    t.evidence('Claims audit', { claims: Object.keys(payload), offendingKeys })
    expect(offendingKeys).toEqual([])

    await t.flush()
  })
})
```

## Adapt

- Replace the token source with how your project exposes the raw access token.
- If you have a separate identification endpoint (e.g. `/auth/profile`) fetched on login, mention in the spec that the PII travels through that call (authenticated, `no-store`), not through the JWT.
- Extend the `forbidden` regex with project-specific fields.
- If the SPA never decodes the JWT, move this test to the N/A spec with reason "SPA treats the token as opaque; backend owns the claims."
