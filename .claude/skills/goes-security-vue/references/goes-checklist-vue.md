# GOES Cybersecurity Checklist — Vue.js Frontend

Each item MUST have at least 1 test. Traceability tag: `GOES Checklist Rxx`.

## Category 1: Web Content

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| R3 | No sensitive data (keys, IDs, personal info) in source files or bundles | Security | Sensitive Data Exposure | critical |
| R4 | No sensitive JS logic or business rules exposed in client-side code | Security | Business Logic Exposure | critical |
| R5 | Sanitize all user input (test XSS injection via v-html, innerHTML, dynamic rendering) | Security | XSS Prevention | blocker |
| R6 | Configure robots.txt and sitemap.xml if public site | Configuration | Public Site Config | minor |

## Category 2: Input/Output Validation

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| R8 | Generic error messages to users (never expose stack traces, API internals) | Security | Generic Error Messages | critical |
| R10 | Remove all console.log/console.error in production builds | Security | Log Exposure Prevention | critical |
| R11 | Input validation: type, length, format, range on all form fields | Domain | Input Validation | critical |

## Category 3: Authentication & Session Management

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| R13 | Token lifetime: short-lived access tokens, refresh token rotation | Security | Token Lifetime | critical |
| R20 | NO sensitive data stored in JWT payload (decoded on client) | Security | JWT Payload Security | critical |
| R21 | Block forced navigation to routes user should not access | Authentication | Route Guard Protection | critical |
| R22 | 404 page for any undefined route | Configuration | Unknown Route Handling | normal |
| R23 | IDOR prevention: never trust URL params for authorization | Security | IDOR Prevention | blocker |
| R24 | Low-privilege users cannot access admin routes/components | Authentication | Privilege Escalation Prevention | blocker |
| R33 | Validate token on every private route navigation | Authentication | Token Validation Per Route | blocker |
| R34 | RBAC: role-based rendering and route protection | Authentication | Role-Based Access Control | blocker |
| R35 | Session inactivity timeout: redirect to login after idle time | Security | Session Inactivity Timeout | critical |

## Category 4: Configuration & Headers

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| R42 | Tokens stored in httpOnly cookies (NOT localStorage/sessionStorage) | Security | Secure Token Storage | blocker |
| R43 | Debug/devtools disabled in production builds | Configuration | Debug Mode Disabled | critical |
| R44 | Content-Security-Policy meta tag or header configured | Configuration | CSP Configuration | critical |
| R50 | Cache-Control: no-store for sensitive API responses | Configuration | Cache Control | critical |

## Category 5: Frontend-Specific Security

| ID | Task | Epic | Feature | Severity |
|----|------|------|---------|----------|
| VF1 | No use of v-html with unsanitized user input | Security | XSS via v-html | blocker |
| VF2 | All forms use CSRF protection tokens | Security | CSRF Prevention | critical |
| VF3 | API interceptor adds auth header to every private request | Authentication | API Auth Interceptor | blocker |
| VF4 | API interceptor handles 401 (redirect to login, clear tokens) | Authentication | 401 Error Handling | critical |
| VF5 | API interceptor handles 403 (show forbidden, no retry) | Authentication | 403 Error Handling | critical |
| VF6 | Environment variables: no secrets in VITE_* variables | Security | Env Variable Security | blocker |
| VF7 | Sensitive data not persisted in Pinia/Vuex store after logout | Security | Store Cleanup on Logout | critical |
| VF8 | Navigation guards check auth state before route enter | Authentication | Navigation Guard Auth | blocker |
| VF9 | Lazy-loaded routes for admin sections (code splitting) | Security | Admin Code Splitting | normal |
| VF10 | No hardcoded API keys, tokens, or secrets in source code | Security | Hardcoded Secrets | blocker |

---

## OWASP Top 10 — Frontend Mapping

| ID | Vulnerability | Frontend Tests | Tag |
|----|--------------|----------------|-----|
| A01 | Broken Access Control | Route guards, RBAC, forced navigation, IDOR in URL params | OWASP A01 |
| A02 | Cryptographic Failures | Token storage, sensitive data in store/localStorage | OWASP A02 |
| A03 | Injection | XSS via v-html, innerHTML, dynamic content, URL params | OWASP A03 |
| A05 | Security Misconfiguration | CSP, debug mode, console.log in prod, env vars | OWASP A05 |
| A07 | Auth Failures | Token validation, session timeout, 401/403 handling | OWASP A07 |
| A09 | Logging Failures | Console.log exposure, error message leaks | OWASP A09 |
