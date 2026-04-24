# Pattern 13 — Build / Source Audit

**Covers:** `R3`, `R10`, `VF6`, `VF10` · **OWASP:** A05, A09 · **Severity:** blocker / critical

Three sweeping checks over the source tree that catch footguns before they ship to production.

1. **`console.log` / `console.error` in production components** — leak debug info to end users and sometimes sensitive state. No bare `console.*` calls in `src/` except inside `if (import.meta.env.DEV)` blocks.
2. **Hardcoded secrets** — API keys, bearer tokens, AWS ids, Stripe keys, private keys. Even in `src/`, even in comments, even in the `public/` folder. Bundled into the SPA → public.
3. **`VITE_*` env vars with suspicious names** — everything `VITE_*` is **public by design** (ships in the bundle). Any variable named `VITE_SECRET`, `VITE_PRIVATE_KEY`, `VITE_TOKEN` is a misconfiguration waiting to happen.

## Example spec — `tests/security/build-source-audit.security-html.spec.ts`

```typescript
/**
 * Build / Source audit — static sweep of the repo
 * ────────────────────────────────────────────────
 * Three defensive checks that run without a browser:
 *   1. No `console.*` in production components (src/).
 *   2. No hardcoded secrets / API keys in the bundle surface.
 *   3. No VITE_* env vars with names that imply secrets.
 *
 * Each failure points at the exact file + line so the author can
 * fix it in seconds.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { report } from '@security-reporter/metadata'

function walk(dir: string, extensions: string[], acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry)
    let isDir = false
    try { isDir = statSync(full).isDirectory() } catch { continue }
    if (isDir) walk(full, extensions, acc)
    else if (extensions.some((ext) => full.endsWith(ext))) acc.push(full)
  }
  return acc
}

const SRC = path.resolve(__dirname, '..', '..', 'src')
const ALL_SOURCE = walk(SRC, ['.vue', '.ts', '.tsx', '.js'])

describe('[GOES Security FE] build/source audit', () => {
  it('[R10] NO console.log / console.error in production components', async () => {
    const t = report()
    t.epic('Log Exposure Prevention')
    t.feature('Production console hygiene')
    t.story('No bare console.* outside DEV guards')
    t.severity('critical')
    t.tag('Pentest', 'OWASP-A09', 'GOES-R10')
    t.descriptionHtml(
      '<p>Debug output in the bundled app leaks implementation details ' +
        '(and sometimes tokens) to end users. Console calls are allowed ' +
        'ONLY inside <code>if (import.meta.env.DEV) { … }</code> blocks, ' +
        'which get stripped by Vite in production builds.</p>',
    )

    const offenders: { file: string; line: number; text: string }[] = []
    const consoleRegex = /\bconsole\.(log|debug|info|warn|error|table)\s*\(/g

    for (const file of ALL_SOURCE) {
      const src = readFileSync(file, 'utf8')
      let match: RegExpExecArray | null
      while ((match = consoleRegex.exec(src)) !== null) {
        const lineStart = src.lastIndexOf('\n', match.index) + 1
        const lineEnd = src.indexOf('\n', match.index)
        const line = src.slice(0, match.index).split('\n').length
        const text = src.slice(lineStart, lineEnd === -1 ? undefined : lineEnd)
        // Skip lines that are obviously dev-only.
        if (/import\.meta\.env\.DEV|process\.env\.NODE_ENV/.test(text)) continue
        if (/^\s*\/\//.test(text)) continue // commented out
        offenders.push({
          file: file.replace(SRC, 'src'),
          line,
          text: text.trim().slice(0, 120),
        })
      }
    }

    t.evidence('Scan result', {
      filesScanned: ALL_SOURCE.length,
      offenders,
    })
    expect(offenders).toEqual([])

    await t.flush()
  })

  it('[VF10] NO hardcoded secrets (API keys, bearer tokens, private keys)', async () => {
    const t = report()
    t.epic('Secrets Hygiene')
    t.feature('Hardcoded secret sweep')
    t.story('No literal keys / tokens in the source tree')
    t.severity('blocker')
    t.tag('Pentest', 'OWASP-A05', 'GOES-R3', 'GOES-VF10')
    t.descriptionHtml(
      '<p>A Vue SPA bundle is fully public. Anything committed to ' +
        '<code>src/</code> ships to the browser verbatim — even strings ' +
        'used only by tests can leak if an attacker opens devtools. This ' +
        'sweep flags the common shapes of accidentally-committed secrets.</p>',
    )

    // Patterns deliberately chosen to have low false-positive rate.
    const patterns: Array<{ name: string; re: RegExp }> = [
      { name: 'AWS access key',        re: /AKIA[0-9A-Z]{16}/ },
      { name: 'Stripe secret key',     re: /sk_(live|test)_[0-9a-zA-Z]{24,}/ },
      { name: 'GitHub token',          re: /gh[pousr]_[A-Za-z0-9_]{36,}/ },
      { name: 'Slack bot token',       re: /xox[abprs]-[A-Za-z0-9-]{10,}/ },
      { name: 'Private key block',     re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
      { name: 'Literal Bearer token',  re: /Bearer\s+eyJ[A-Za-z0-9_-]+\./ },
      // Adjust the list to the real services your project talks to.
    ]

    const offenders: { file: string; line: number; type: string }[] = []
    for (const file of ALL_SOURCE) {
      const src = readFileSync(file, 'utf8')
      for (const { name, re } of patterns) {
        const m = re.exec(src)
        if (m) {
          const line = src.slice(0, m.index).split('\n').length
          offenders.push({
            file: file.replace(SRC, 'src'),
            line,
            type: name,
          })
        }
      }
    }

    t.evidence('Scan result', { filesScanned: ALL_SOURCE.length, offenders })
    expect(offenders).toEqual([])

    await t.flush()
  })

  it('[VF6] NO VITE_* env vars with suspicious names', async () => {
    const t = report()
    t.epic('Env Variable Security')
    t.feature('Client-public env audit')
    t.story('Vite env vars that look like secrets are fail-closed')
    t.severity('blocker')
    t.tag('Pentest', 'OWASP-A05', 'GOES-VF6')
    t.descriptionHtml(
      '<p>Every <code>VITE_*</code> variable is inlined into the bundle ' +
        'by Vite. There is no such thing as a "private" VITE var; if a ' +
        'name implies a secret (SECRET / PRIVATE / PASSWORD / TOKEN) the ' +
        'author probably misunderstood the boundary. Fail the build.</p>',
    )

    const suspect = /^(VITE_).*(SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|API_KEY)/i

    const offenders = Object.keys(import.meta.env)
      .filter((k) => suspect.test(k))

    t.evidence('Env snapshot', {
      totalViteVars: Object.keys(import.meta.env).filter((k) => k.startsWith('VITE_')).length,
      offenders,
    })
    expect(offenders).toEqual([])

    await t.flush()
  })
})
```

## Adapt

- Expand the `patterns` list with the real services the project integrates (e.g. Twilio, SendGrid, Auth0).
- If the project uses `console.log` intentionally for audit/telemetry, wrap those calls in a logger module and allow-list that single module path in the offenders filter.
- If the project deploys with a secrets-injection step at runtime (not VITE_), document the boundary in the N/A spec.
