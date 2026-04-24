# Pattern 03 — Client-side XSS Prevention

**Covers:** `R5`, `R11`, `VF1` · **OWASP:** A03 · **Severity:** blocker

Defence-in-depth: the backend strips unsafe markup, AND the frontend rejects it before the network round-trip so the user sees a quick, specific error — and if the backend filter ever fails, the XSS still never reaches the DOM.

The helper `containsUnsafeHtml` covers three vectors:

- HTML tags: `<script>`, `<img>`, `<iframe>`, comments
- Inline event handlers: `onclick=`, `onerror=`, `onload=`, etc.
- Script-capable URL schemes: `javascript:`, `vbscript:`, `data:text/html`

Plus `firstUnsafeKey(obj)` returns a dotted path of the offending field so the form can highlight it precisely.

## Example spec — `tests/security/sanitize.security-html.spec.ts`

```typescript
/**
 * Client-side XSS Prevention — sanitize.ts
 * ─────────────────────────────────────────
 * The app ships defence-in-depth: the backend interceptor strips
 * unsafe markup, and the frontend rejects it client-side before
 * the network round-trip so the user sees a quick, specific error.
 *
 * These tests pin down the three regex vectors used by
 * `containsUnsafeHtml` + the traversal behaviour of
 * `firstUnsafeKey`. They guard against regressions like "devs
 * relaxed the tag regex and now <img onerror> slips through".
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
        'prevent reflected and stored XSS in case the backend ' +
        'interceptor ever fails (defence in depth).</p>',
    )

    expect(containsUnsafeHtml('<script>alert(1)</script>')).toBe(true)
    expect(containsUnsafeHtml('<img src=x>')).toBe(true)
    expect(containsUnsafeHtml('<iframe src="//evil"></iframe>')).toBe(true)
    expect(containsUnsafeHtml('<!-- comment -->')).toBe(true)

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
        '<code>onerror=\'alert(1)\'</code> are caught by the event ' +
        'handler regex and blocked.</p>',
    )

    // The regex requires a leading whitespace before `on*` to avoid
    // false positives on words like "onion" or "button". These are
    // the realistic shapes attackers use (inside a tag or after an
    // opening quote).
    expect(containsUnsafeHtml(' onclick="do()"')).toBe(true)
    expect(containsUnsafeHtml(" onerror='alert(1)'")).toBe(true)
    expect(containsUnsafeHtml(' onload=boom')).toBe(true)
    expect(containsUnsafeHtml(' onmouseover = "x"')).toBe(true)
    // Inside a tag, TAG_REGEX already catches it — guard against
    // a plain `onclick` without whitespace not triggering the
    // handler regex alone.
    expect(containsUnsafeHtml('<a onclick="do()">x</a>')).toBe(true)
    // Sanity: the word "button" alone must NOT trigger.
    expect(containsUnsafeHtml('button pressed')).toBe(false)

    await t.flush()
  })

  it('[R11] rejects script-capable URL schemes (javascript:, data:text/html, vbscript:)', async () => {
    const t = report()
    t.epic('Input Validation')
    t.feature('Client-side sanitization')
    t.story('Script schemes rejected')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A03', 'GOES-R11')

    expect(containsUnsafeHtml('javascript:alert(1)')).toBe(true)
    expect(containsUnsafeHtml('JavaScript:alert(1)')).toBe(true)
    expect(containsUnsafeHtml('vbscript:msgbox(1)')).toBe(true)
    expect(containsUnsafeHtml('data:text/html,<script>')).toBe(true)

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
        'observation must pass through — it is not an XSS vector and ' +
        'false-positives on these degrade the UX.</p>',
    )

    expect(containsUnsafeHtml('a<b')).toBe(false)
    expect(containsUnsafeHtml('x > 5')).toBe(false)
    expect(containsUnsafeHtml('< 5 rows')).toBe(false)
    expect(containsUnsafeHtml('')).toBe(false)
    expect(containsUnsafeHtml(null)).toBe(false)
    expect(containsUnsafeHtml(undefined)).toBe(false)

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
        'notation (<code>migration.observations</code>).</p>',
    )

    expect(
      firstUnsafeKey({ name: 'SIGES', description: '<script>x</script>' }),
    ).toBe('description')

    expect(
      firstUnsafeKey({
        system: { code: 'OK' },
        migration: { observations: '<img onerror=1>' },
      }),
    ).toBe('migration.observations')

    expect(firstUnsafeKey({ name: 'ok', description: 'x > 5' })).toBeNull()

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
      '<p>The validation message is generic. Saying ' +
        '"contains HTML/scripts" would tell an attacker the exact ' +
        'pattern being checked, so we avoid it.</p>',
    )

    expect(INVALID_INPUT_MESSAGE).not.toMatch(/html|script|tag|regex/i)
    expect(INVALID_INPUT_MESSAGE.length).toBeGreaterThan(0)

    await t.flush()
  })
})
```

## Adapt

- Replace `@/shared/utils/sanitize` with your project's sanitizer helper.
- If your project uses DOMPurify, add extra assertions that the sanitized output is what you expect (not just a pass/fail boolean).
- Ensure `INVALID_INPUT_MESSAGE` in your codebase is equally generic — no mention of "html", "script", "regex" etc.
