# Pattern 03 — Client-side XSS Prevention

**Covers:** `R5`, `R11`, `VF1` · **OWASP:** A03 · **Severity:** blocker

Defence-in-depth: the backend strips unsafe markup, AND the frontend rejects it before the network round-trip. The helper `containsUnsafeHtml` covers three vectors:

- HTML tags: `<script>`, `<img>`, `<iframe>`, comments
- Inline event handlers: `onclick=`, `onerror=`, `onload=`, etc.
- Script-capable URL schemes: `javascript:`, `vbscript:`, `data:text/html`

Plus `firstUnsafeKey(obj)` returns a dotted path of the offending field so the form can highlight it precisely. Every payload tested gets logged as `Input - attacker payloads`, the regex decisions are captured in `Output - defense result`.

## Example spec — `tests/security/sanitize.security-html.spec.ts`

```typescript
/**
 * Client-side XSS Prevention - sanitize.ts
 * ─────────────────────────────────────────
 * The app ships defence-in-depth: the backend interceptor strips
 * unsafe markup, and the frontend rejects it client-side before
 * the network round-trip so the user sees a quick, specific error.
 *
 * These tests pin down the three regex vectors used by
 * `containsUnsafeHtml` + the traversal behaviour of
 * `firstUnsafeKey`.
 */
import { describe, expect, it } from 'vitest'
import { report } from '@security-reporter/metadata'
import {
  INVALID_INPUT_MESSAGE,
  containsUnsafeHtml,
  firstUnsafeKey,
} from '@/shared/utils/sanitize'

describe('[GOES Security FE] sanitize.ts · Client-side XSS guard', () => {
  it('[R11] rejects HTML tags (<script>, <img>, <iframe>)', async () => {
    const t = report()
    t.epic('Input Validation')
    t.feature('Client-side sanitization')
    t.story('HTML tags rejected before submit')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A03', 'GOES-R11')
    t.descriptionHtml(
      '<p>Opening or closing HTML tags are rejected before submit to ' +
        'prevent reflected and stored XSS in case the backend interceptor ' +
        'ever fails (defence in depth).</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener">OWASP A03</a>.</p>',
    )

    const payloads = [
      '<script>alert(1)</script>',
      '<img src=x>',
      '<iframe src="//evil"></iframe>',
      '<!-- comment -->',
    ]
    t.evidence('attacker payloads (input)', { payloads })

    t.step('Execute: run each payload through containsUnsafeHtml')
    const results = payloads.map((p) => ({
      payload: p,
      rejected: containsUnsafeHtml(p),
    }))

    t.step('Verify: every payload is rejected')
    for (const { payload } of results)
      expect(containsUnsafeHtml(payload)).toBe(true)

    t.evidence('defense result (output)', {
      allRejected: results.every((r) => r.rejected),
      breakdown: results,
    })

    await t.flush()
  })

  it('[R11] rejects inline event handlers (onclick, onerror, onload)', async () => {
    const t = report()
    t.epic('Input Validation')
    t.feature('Client-side sanitization')
    t.story('Inline event handlers rejected')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A03', 'GOES-R11')
    t.descriptionHtml(
      '<p>Strings such as <code>onclick="x"</code> or ' +
        "<code>onerror='alert(1)'</code> are caught by the event " +
        'handler regex and blocked.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener">OWASP A03</a>.</p>',
    )

    const payloads = [
      ' onclick="do()"',
      " onerror='alert(1)'",
      ' onload=boom',
      ' onmouseover = "x"',
      '<a onclick="do()">x</a>',
    ]
    t.evidence('attacker payloads (input)', {
      payloads,
      note: 'leading whitespace required by the regex to avoid false positives on words like "button"',
    })

    t.step('Execute + Verify: every handler payload flagged')
    for (const p of payloads) expect(containsUnsafeHtml(p)).toBe(true)

    t.step('Verify: the word "button pressed" is NOT flagged (sanity)')
    const benign = containsUnsafeHtml('button pressed')
    expect(benign).toBe(false)

    t.evidence('defense result (output)', {
      payloadsBlocked: payloads.length,
      benignFalsePositiveCheck: benign === false ? 'passed' : 'FAILED',
    })

    await t.flush()
  })

  it('[R11] rejects script-capable URL schemes (javascript:, data:text/html, vbscript:)', async () => {
    const t = report()
    t.epic('Input Validation')
    t.feature('Client-side sanitization')
    t.story('Script schemes rejected')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A03', 'GOES-R11')
    t.descriptionHtml(
      '<p>Protocol schemes capable of executing script must be blocked ' +
        'regardless of context.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener">OWASP A03</a>.</p>',
    )

    const payloads = [
      'javascript:alert(1)',
      'JavaScript:alert(1)',
      'vbscript:msgbox(1)',
      'data:text/html,<script>',
    ]
    t.evidence('attacker payloads (input)', { payloads })

    t.step('Execute + Verify: every scheme payload flagged')
    for (const p of payloads) expect(containsUnsafeHtml(p)).toBe(true)

    t.evidence('defense result (output)', {
      payloadsBlocked: payloads.length,
    })

    await t.flush()
  })

  it('[R11] does NOT flag benign `<` and `>` used as comparisons', async () => {
    const t = report()
    t.epic('Input Validation')
    t.feature('Client-side sanitization')
    t.story('Non-tag `<` / `>` are preserved')
    t.severity('normal')
    t.tag('Pentest', 'OWASP-A03', 'GOES-R11')
    t.descriptionHtml(
      '<p>Writing <code>a<b</code> or <code>x > 5</code> in a free-text ' +
        'observation must pass through - it is not an XSS vector and ' +
        'false-positives on these degrade the UX.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener">OWASP A03</a>.</p>',
    )

    const inputs = ['a<b', 'x > 5', '< 5 rows', '', null, undefined]
    t.evidence('benign comparison/null variants (input)', { inputs })

    t.step('Execute + Verify: every benign input must be accepted')
    for (const v of inputs) expect(containsUnsafeHtml(v as string)).toBe(false)

    t.evidence('defense result (output)', {
      falsePositives: 0,
      inputsTested: inputs.length,
    })

    await t.flush()
  })

  it('[R11] firstUnsafeKey returns dotted path of the offending field', async () => {
    const t = report()
    t.epic('Input Validation')
    t.feature('Client-side sanitization')
    t.story('Offending field is precisely located')
    t.severity('normal')
    t.tag('Pentest', 'OWASP-A03', 'GOES-R11')
    t.descriptionHtml(
      '<p>The form tells the user exactly which field contains the ' +
        'invalid payload. Nested objects are reported with dotted ' +
        'notation (<code>migration.observations</code>).</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener">OWASP A03</a>.</p>',
    )

    t.step('Prepare: three payloads — flat, nested, clean')
    const flatPayload = { name: 'SIGES', description: '<script>x</script>' }
    const nestedPayload = {
      system: { code: 'OK' },
      migration: { observations: '<img onerror=1>' },
    }
    const cleanPayload = { name: 'ok', description: 'x > 5' }
    t.evidence('payloads (input)', { flatPayload, nestedPayload, cleanPayload })

    t.step('Execute: firstUnsafeKey on each')
    const flatResult = firstUnsafeKey(flatPayload)
    const nestedResult = firstUnsafeKey(nestedPayload)
    const cleanResult = firstUnsafeKey(cleanPayload)

    t.step(
      'Verify: dotted path is returned for offending fields; null for clean',
    )
    expect(flatResult).toBe('description')
    expect(nestedResult).toBe('migration.observations')
    expect(cleanResult).toBeNull()

    t.evidence('firstUnsafeKey results (output)', {
      flat: flatResult,
      nested: nestedResult,
      clean: cleanResult,
    })

    await t.flush()
  })

  it('[R8] INVALID_INPUT_MESSAGE does NOT leak the detection surface', async () => {
    const t = report()
    t.epic('Error Information Disclosure Prevention')
    t.feature('Generic error messages')
    t.story('Validation message is vague on purpose')
    t.severity('high')
    t.tag('Pentest', 'OWASP-A05', 'GOES-R8')
    t.descriptionHtml(
      '<p>The validation message is generic. Saying "contains HTML/scripts" ' +
        'would tell an attacker the exact pattern being checked, so we avoid it.</p>' +
        '<p><strong>Reference:</strong> <a href="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" target="_blank" rel="noopener">OWASP A05</a>.</p>',
    )

    t.evidence('copy under audit (input)', {
      message: INVALID_INPUT_MESSAGE,
      forbiddenTokens: ['html', 'script', 'tag', 'regex'],
    })

    t.step('Verify: message is non-empty AND contains no detection hints')
    expect(INVALID_INPUT_MESSAGE).not.toMatch(/html|script|tag|regex/i)
    expect(INVALID_INPUT_MESSAGE.length).toBeGreaterThan(0)

    t.evidence('defense result (output)', {
      messageLength: INVALID_INPUT_MESSAGE.length,
      leaksDetectionSurface: /html|script|tag|regex/i.test(
        INVALID_INPUT_MESSAGE,
      ),
    })

    await t.flush()
  })
})
```

## Adapt to your project

- Replace `@/shared/utils/sanitize` with your project's sanitizer helper.
- If your project uses DOMPurify, add extra assertions that the sanitized output is what you expect (not just a pass/fail boolean).
- Ensure `INVALID_INPUT_MESSAGE` in your codebase is equally generic — no mention of "html", "script", "regex" etc.
