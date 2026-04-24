# Severity Assignment Guide

| Severity | When to use | Example |
|----------|-------------|---------|
| `blocker` | If the test fails, the app is shippably insecure. | XSS possible, route guard bypassed, token stored in localStorage, open-redirect honoured. |
| `critical` | A critical user-facing flow or regulatory requirement is broken. | Idle timeout does not fire, 401 handler does not clear auth state, generic-error rule leaks data. |
| `high` | Defense-in-depth control missing. | Autocomplete "off" on password fields, no v-html audit, missing CSP report-only. |
| `normal` | Standard functional expectation. | Unknown route returns 404 view, form field validates length. |
| `minor` | Cosmetic or edge case. | Message wording, label capitalization. |

## Rule of thumb

If an auditor would flag the failure, use `critical` or `blocker`. Reserve `normal` / `minor` for things that a reasonable team could defer a sprint without consequences.
