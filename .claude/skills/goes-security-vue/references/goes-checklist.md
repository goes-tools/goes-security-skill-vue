# GOES Cybersecurity Checklist — Vue.js Frontend

Each item MUST have at least 1 test (or an explicit N/A entry in `not-applicable.security-html.spec.ts`). Traceability tag format: `GOES Checklist Rxx` / `GOES-Rxx` / `GOES-VFx`.

## Category 1: Web Content

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| R3 | No sensitive data (keys, IDs, personal info) in source or bundles | Security | Sensitive Data Exposure | critical |
| R4 | No sensitive JS logic or business rules exposed in client code | Security | Business Logic Exposure | critical |
| R5 | Sanitize all user input (XSS via v-html, innerHTML, dynamic rendering) | Security | XSS Prevention | blocker |
| R6 | Configure robots.txt and sitemap.xml if public | Configuration | Public Site Config | minor |

## Category 2: Input/Output Validation

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| R8 | Generic error messages (never expose stack traces / API internals / user enumeration) | Security | Generic Error Messages | critical |
| R10 | Remove all `console.log` / `console.error` from production builds | Security | Log Exposure Prevention | critical |
| R11 | Client-side input validation (type, length, format, range) | Domain | Input Validation | critical |

## Category 3: Authentication & Session Management

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| R9 | RBAC check at the router AND at render time (`can()` / `hasRole()`) | Access Control | RBAC | blocker |
| R13 | Token lifetime: short-lived access tokens, refresh rotation | Security | Token Lifetime | critical |
| R14 | Auth failures: autocomplete hygiene, no token in Web Storage | Security | Auth Failure Handling | blocker |
| R20 | NO sensitive data in JWT payload (decoded client-side by tooling) | Security | JWT Payload Security | critical |
| R21 | Router guard blocks forced navigation to protected routes | Access Control | Forced Browsing Prevention | critical |
| R22 | 404 page for undefined routes | Configuration | Unknown Route Handling | normal |
| R23 | IDOR prevention: never trust URL params for authorization | Security | IDOR Prevention | blocker |
| R24 | Low-privilege users cannot access admin routes / components | Access Control | Privilege Escalation Prevention | blocker |
| R32 | Refresh coordinator: single-flight, cooldown, max attempts | Security | Token Rotation + Anti-Stampede | blocker |
| R33 | Validate session on every private navigation | Access Control | Session Validation Per Route | blocker |
| R34 | Role-based rendering (PERMISOS matrix) | Access Control | Role-Based Rendering | blocker |
| R35 | Idle timeout with warning + forced logout | Security | Session Inactivity Timeout | critical |
| R40 | `withCredentials: true` on API client; bounded timeout | Security | HTTP Client Defaults | critical |

## Category 4: Configuration

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| R42 | Tokens in httpOnly cookies (NOT localStorage / sessionStorage) | Security | Secure Token Storage | blocker |
| R43 | Devtools / debug disabled in production build | Configuration | Debug Mode Disabled | critical |
| R44 | Content-Security-Policy served by backend; verified via meta or smoke test | Configuration | CSP Configuration | critical |
| R50 | Cache-Control: no-store for sensitive responses | Configuration | Cache Control | critical |

## Category 5: Vue-specific Frontend Controls

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| VF1 | No `v-html` with unsanitized user input (sweep `src/` for zero matches) | Security | XSS via v-html | blocker |
| VF2 | Forms use CSRF tokens / SameSite cookies | Security | CSRF Prevention | critical |
| VF3 | API interceptor attaches `Authorization: Bearer` only when token present | Access Control | API Auth Interceptor | blocker |
| VF4 | Interceptor handles 401: refresh flow + redirect to login with `?redirect=` | Access Control | 401 Handling | critical |
| VF5 | Interceptor handles 403: render `/forbidden`, never retry | Access Control | 403 Handling | critical |
| VF6 | No secrets in `VITE_*` env vars (these are public by design) | Security | Env Variable Security | blocker |
| VF7 | Pinia store wipes all sensitive data on logout (token, user, roles, timestamps) | Security | Store Cleanup on Logout | critical |
| VF8 | Router beforeEach guard checks auth state on every navigation | Access Control | Navigation Guard Auth | blocker |
| VF9 | Admin routes lazy-loaded (code splitting prevents bundle leak to anonymous users) | Security | Admin Code Splitting | normal |
| VF10 | No hardcoded API keys, tokens or secrets in source | Security | Hardcoded Secrets | blocker |
| VF11 | Autocomplete hygiene: email = "email"/"username"; password = "current-password" | Security | Credential Autofill | high |
| VF12 | Open-redirect guard: `?redirect=` only honored for site-relative paths | Security | Open Redirect Prevention | critical |

---

## OWASP Top 10 — Frontend Mapping

| ID | Vulnerability | Frontend Tests | Tag |
|----|---------------|----------------|-----|
| A01 | Broken Access Control | Router guards, RBAC, forced navigation, IDOR via URL params, parent-route role inheritance | OWASP-A01 |
| A02 | Cryptographic Failures | Token storage audit (no Web Storage), sensitive data in Pinia after logout | OWASP-A02 |
| A03 | Injection | XSS via v-html, innerHTML, dynamic content, URL params, unsafe HTML sinks | OWASP-A03 |
| A04 | Insecure Design | Client-side rate-limit awareness, idle timeouts, refresh coordinator anti-stampede | OWASP-A04 |
| A05 | Security Misconfiguration | CSP, debug mode, console.log in prod, env vars, CORS + credentials client-side | OWASP-A05 |
| A07 | Auth Failures | Session timeout, 401/403 handling, generic errors, open-redirect, autocomplete | OWASP-A07 |
| A09 | Logging Failures | Console output leaks, error message leaks | OWASP-A09 |

## Server-side controls — out of scope for the SPA

The following GOES items live on the server (NestJS backend). They do NOT apply to the frontend and MUST be documented in `not-applicable.security-html.spec.ts` so the auditor sees they were considered explicitly:

- R15 (password hashing bcrypt/Argon2)
- R16 (JWT RS256 asymmetric signing)
- R17 (session ID entropy ≥ 128 bits)
- R27 (brute-force lockout after N failed logins)
- R7 (rate limiting per IP + endpoint)
- CORS allowlist + credentials policy
- DB-at-rest encryption
- Security HTTP headers (CSP / HSTS / XFO served by the server)
- Inbound webhook signature verification
- PCI-DSS cardholder data handling (if project has no payments)
- File upload validation (magic bytes, size, malware scan) — if the SPA has no `<input type="file">`
