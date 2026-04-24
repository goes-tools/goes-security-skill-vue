# Pattern 09 — Scope Boundaries · Not-Applicable Controls

**Covers:** every server-side control that does NOT apply to the SPA · **Severity:** minor (informational)

Auditors need to see the full control surface and confirm that out-of-scope items were **considered** — never silently missed. This spec documents each control that lives server-side (or is out of scope for product reasons) with its reason and the attack vector it would mitigate if it applied. Entries tagged `N/A` get classified into the "No aplicables" bucket of the HTML report and the Excel workbook.

Typical server-side items to document as N/A for a pure SPA:

- Password hashing (`R15`)
- JWT RS256 signing (`R16`)
- Refresh token entropy (`R17`)
- Brute-force lockout (`R27`)
- Rate limiting (`R7`)
- SQL/NoSQL injection (goes through ORM on the server)
- CORS allowlist + credentials policy
- File upload validation (`R12`, `R57-R60`) — if the SPA has no `<input type="file">`
- DB-at-rest encryption
- Security HTTP response headers (CSP, HSTS, XFO served by the server)
- Inbound webhook signature verification
- PCI-DSS (if the product does not handle payments)

## Example spec — `tests/security/not-applicable.security-html.spec.ts`

```typescript
/**
 * Not Applicable (N/A) Security Controls — Frontend edition
 * ──────────────────────────────────────────────────────────
 * Documents every control from GOES / OWASP Top 10 that lives
 * server-side and therefore cannot be tested from this SPA. Each
 * entry appears in the HTML report under the "Scope boundaries"
 * epic with tag `N/A` so an auditor sees the full surface and
 * confirms the out-of-scope controls were considered — never
 * silently missed.
 *
 * When a responsibility shifts (e.g. we introduce client-side
 * encryption), remove the entry and add a real test in the
 * corresponding spec.
 */
import { describe, it, expect } from 'vitest'
import { report } from '@security-reporter/metadata'

interface NaEntry {
  /** GOES / OWASP identifier. */
  control: string
  /** Short title of the control. */
  title: string
  /** Why this control does not apply to the frontend. */
  reason: string
  /** Attack vector the control would mitigate if it applied. */
  mitigatedVector: string
  /** OWASP Top 10 reference. */
  owasp: string
}

const NOT_APPLICABLE: NaEntry[] = [
  {
    control: 'GOES-R15',
    title: 'Password hashing (bcrypt cost ≥ 12)',
    reason:
      'The frontend never sees the plaintext password beyond the submit boundary — hashing is entirely a backend concern (see portafolio-it-be auth-service R15).',
    mitigatedVector:
      'Plaintext password storage, rainbow-table-assisted credential theft.',
    owasp: 'OWASP A02:2021 — Cryptographic Failures',
  },
  {
    control: 'GOES-R16',
    title: 'JWT RS256 asymmetric signing',
    reason:
      'Token signing is the backend\'s job. The SPA only receives the signed token and forwards it in the Authorization header.',
    mitigatedVector:
      'Token forgery, algorithm-confusion attacks (HS256 with public key as secret).',
    owasp: 'OWASP A02:2021 — Cryptographic Failures',
  },
  {
    control: 'GOES-R17',
    title: 'Refresh token entropy (UUID v4 / 128+ bits)',
    reason:
      'Refresh tokens are generated server-side and travel in an httpOnly cookie the SPA cannot read. Entropy is a backend invariant.',
    mitigatedVector:
      'Brute-force guessing of refresh tokens, token collision.',
    owasp: 'OWASP A02:2021 — Cryptographic Failures',
  },
  {
    control: 'GOES-R27',
    title: 'Brute-force lockout after N failed logins',
    reason:
      'Account lockout lives in the backend login handler. The SPA has no visibility of the failed-attempt counter.',
    mitigatedVector:
      'Credential-stuffing attacks, online brute-force.',
    owasp: 'OWASP A07:2021 — Identification and Authentication Failures',
  },
  {
    control: 'GOES-R7',
    title: 'Rate limiting (per IP + per endpoint)',
    reason:
      'Rate limits are enforced by the NestJS Throttler on the backend. The SPA cannot throttle its own users reliably because anyone can bypass it.',
    mitigatedVector:
      'DoS via burst requests, login flooding.',
    owasp: 'OWASP A04:2021 — Insecure Design',
  },
  {
    control: 'OWASP-A03-SQLi',
    title: 'SQL / NoSQL injection',
    reason:
      'All database access goes through Prisma on the backend. The frontend never builds SQL and cannot trigger injection.',
    mitigatedVector:
      'Arbitrary query execution against the database.',
    owasp: 'OWASP A03:2021 — Injection',
  },
  {
    control: 'GOES-CORS',
    title: 'CORS allowlist + credentials policy',
    reason:
      'CORS is configured in `main.ts` of the backend (Nest). The SPA is subject to whatever policy the server declares and has no say.',
    mitigatedVector:
      'Cross-origin data leakage, drive-by browser requests from malicious sites.',
    owasp: 'OWASP A05:2021 — Security Misconfiguration',
  },
  {
    control: 'GOES-R12',
    title: 'File upload validation (magic bytes, size, malware scan)',
    reason:
      'The app exposes zero upload endpoints. No `<input type="file">` in source, no FormData with blobs (verified by grep across src/).',
    mitigatedVector:
      'Malicious uploads (polyglot PDFs, SVG XXE, oversized DoS).',
    owasp: 'OWASP A04:2021 — Insecure Design',
  },
  {
    control: 'GOES-DB-ENC',
    title: 'Data-at-rest encryption of sensitive columns',
    reason:
      'Encryption at rest is a database-level concern (TDE / column encryption on the PostgreSQL server). The SPA does not own storage.',
    mitigatedVector:
      'Disk theft / DB snapshot leak exposing plaintext data.',
    owasp: 'OWASP A02:2021 — Cryptographic Failures',
  },
  {
    control: 'GOES-Security-Headers',
    title: 'Security HTTP headers (CSP, HSTS, X-Frame-Options)',
    reason:
      'Response headers are set by the Nest middleware (`helmet` + custom CSP in the backend). The SPA receives them but cannot set them on its own responses — there are none, it is a static build.',
    mitigatedVector:
      'Clickjacking, MITM downgrade, inline script injection, mixed content.',
    owasp: 'OWASP A05:2021 — Security Misconfiguration',
  },
  {
    control: 'GOES-R35',
    title: 'Inbound webhook signature verification',
    reason:
      'No inbound webhooks exist in this product (verified by searching POST handlers in the backend).',
    mitigatedVector:
      'Spoofed third-party callbacks (Stripe, GitHub, etc.).',
    owasp: 'OWASP A08:2021 — Software and Data Integrity Failures',
  },
  {
    control: 'PCI-DSS',
    title: 'Cardholder / payment data handling',
    reason:
      'The app does not process payments or store card data. No `card`, `payment`, `stripe`, `iban` in the codebase.',
    mitigatedVector:
      'PCI data exfiltration, PAN leakage.',
    owasp: 'PCI-DSS v4.0',
  },
]

describe('[Scope boundaries FE] Server-side controls NOT applicable to the frontend', () => {
  for (const entry of NOT_APPLICABLE) {
    it(`[N/A ${entry.control}] ${entry.title}`, async () => {
      const t = report()
      t.epic('Scope boundaries')
      t.feature('Not applicable — server-side control')
      t.story(entry.title)
      t.severity('minor')
      t.owner('Security Team')
      t.tag('N/A', 'Scope', entry.control)
      t.label('compliance', 'GOES')
      t.label('status', 'not-applicable')
      t.suite('Scope boundaries')
      t.parentSuite('Security Controls')

      t.descriptionHtml(
        '<h4>Not applicable · ' +
          entry.control +
          '</h4>' +
          '<p><strong>Control:</strong> ' +
          entry.title +
          '</p>' +
          '<p><strong>Reason:</strong> ' +
          entry.reason +
          '</p>' +
          '<p><strong>Vector it would mitigate if it applied:</strong> ' +
          entry.mitigatedVector +
          '</p>' +
          '<p><strong>Reference:</strong> ' +
          entry.owasp +
          '</p>' +
          '<p class="hint"><em>If the frontend ever absorbs this ' +
          'responsibility (e.g. client-side crypto, uploads), remove ' +
          'the entry from here and add a real test in the ' +
          'corresponding spec.</em></p>',
      )

      t.evidence('Evidence — scope exclusion', {
        control: entry.control,
        status: 'NOT_APPLICABLE',
        title: entry.title,
        reason: entry.reason,
        mitigatedVector: entry.mitigatedVector,
        owasp: entry.owasp,
      })

      // Trivial assertion so the entry counts as "passed" with
      // metadata visible under its epic/feature/story.
      expect(entry.reason.length).toBeGreaterThan(0)
      await t.flush()
    })
  }
})
```

## Golden rule

Keep the list **short and honest**. Adding N/A entries without a real product reason waters down the report and erodes the auditor's trust. If a responsibility moves client-side (e.g. the product starts accepting uploads), remove the entry from here and add a real test in the corresponding spec.
