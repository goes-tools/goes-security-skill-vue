---
name: goes-security-testing-vue
description: "Genera tests de seguridad para proyectos Vue 3 + Vitest + Playwright con un Custom HTML + Excel Reporter (sin Java ni Allure) cubriendo el Checklist de Ciberseguridad GOES (items frontend), OWASP Top 10 y controles especificos de SPA (VF1-VF12). Configura Vitest + custom reporter y crea specs completas con evidence input/output (payload del atacante + respuesta de defensa), narrativa Prepare/Execute/Verify, links canonicos a owasp.org, classification por epicas/severidad, y modal con la ruta del spec. Buckets: Pasados / Desactivados / Migrados / No aplicables. Ademas configura un README profesional, .env.example, ESLint ignore para el reporter bundled, husky pre-commit hooks, login con card design + dark mode toggle, ThemeToggle con variant prop topbar/default, paginacion + busqueda client-side en catalogos chicos, y politica de NO-emojis (todos los iconos UI usan Lucide). Activar cuando el usuario pida: tests de seguridad frontend, tests de seguridad Vue, checklist GOES frontend, pentest tests frontend, security specs Vue, reporte de seguridad HTML o Excel para Vue, security report frontend, hardening Vue SPA, o cualquier variante."
---

# GOES Security Testing — Skill para Vue 3 + Vitest + Playwright

## Resumen

Este skill genera tests de seguridad **profesionales** para proyectos Vue 3 + Vitest (unit) y Playwright (E2E) con un Custom HTML + Excel Reporter, sin Java ni Allure. Cubre los items frontend del Checklist de Ciberseguridad GOES, OWASP Top 10 y controles especificos de SPA (VF1-VF12).

Ademas del codigo de tests, el skill aplica una serie de **practicas de hardening del proyecto** que aprendimos auditando portafolio-it-fe (un SPA real de MINEDUCYT). Esas practicas estan documentadas como reglas obligatorias en el PASO 8.

El reporter produce DOS artefactos autocontenidos:

- **HTML** (`reports/security/security-report.html`)
  - Sidebar con navegacion por Epic > Feature > Story
  - Modal de detalle con severity badges, tags, **ruta del spec** (📄 archivo), steps Prepare/Execute/Verify y evidencia JSON con syntax highlighting
  - Graficos SVG (pie de pass/fail, barras por severity, donut OWASP)
  - Buckets: Pasados / Desactivados / Migrados / No aplicables
  - Tema oscuro, busqueda en tiempo real
- **Excel** (`reports/security/security-report.xlsx`)
  - Una hoja por bucket, una fila por test con todos los campos de metadata, tags y la columna "Archivo"
  - Ideal como anexo de auditoria regulatoria

---

## PASO 1: Analizar el proyecto

Antes de generar codigo, analizar la estructura real del proyecto Vue:

```
1. Leer package.json para identificar:
   - Framework (vue 3)
   - Test runner (vitest — si no existe, instalarlo)
   - "type": "module" — si esta, el reporter DEBE cargarse como .cjs
   - Dependencias de auth: pinia, vue-router, axios
   - Package manager: pnpm-lock.yaml | yarn.lock | package-lock.json

2. Listar estructura:
   - Glob src/views/**/*.vue  o  src/pages/**/*.vue — vistas/paginas
   - Glob src/components/**/*.vue — componentes
   - Glob src/router/**/*.ts — rutas y guards
   - Glob src/stores/**/*.ts  o  src/features/**/stores/**/*.ts — stores Pinia
   - Glob src/composables/**/*.ts — composables (auth, api, activity, idle)
   - Glob src/lib/**/*.ts  o  src/services/**/*.ts — api client, interceptors

3. Identificar que ya existe:
   - Archivos .spec.ts / .test.ts existentes
   - Configuracion de Vitest actual
   - Playwright configurado? (playwright.config.ts)
   - Husky + lint-staged? (.husky/pre-commit)
   - ESLint flat config con tokens semanticos?
```

---

## PASO 2: Instalar dependencias

Detectar el package manager por lock file y solo instalar lo que falte:

```bash
# Reemplazar PKG por npm | pnpm | yarn segun corresponda
PKG add -D vitest @vue/test-utils jsdom xlsx
PKG add -D @playwright/test  # solo si van a generarse E2E
```

`xlsx` (SheetJS) es usado por el reporter para generar el Excel (`security-report.xlsx`) en paralelo al HTML.

**NO instalar Allure, allure-vitest ni allure-commandline.**

### Playwright binarios

Despues del primer `npm install`, ejecutar (una sola vez, ~150 MB):

```bash
npx playwright install
```

Sin esto los E2E fallan con `Executable doesn't exist`. Recomendado: agregar a un script `prepare` o documentarlo en el README del proyecto.

---

## PASO 3: Configurar el custom reporter

Este skill incluye el reporter bundled en `.claude/skills/goes-security-vue/reporter/`. **NO copiar los archivos** — referenciarlos directamente.

El reporter consiste en dos archivos:

- **`reporter/html-reporter.cjs`** — Vitest custom reporter (JavaScript puro). Soporta Vitest v4 (`onTestRunEnd`) con fallback para v3 (`onFinished`) y Jest legacy (`onRunComplete`). Genera HTML + Excel.
- **`reporter/metadata.ts`** — Collector de metadata. Exporta `report()` y `AllureCompat`. Cada test registra epic, feature, story, severity, tags, steps, evidencia.

**NO modificar los archivos del reporter.**

### Por que `.cjs` y no `.js`?

Proyectos generados con `create-vue`/Vite llevan `"type": "module"` en `package.json`. Bajo ese modo Node trata los `.js` como ESM; Jest/Vitest custom reporters son CommonJS. La extension `.cjs` fuerza parseo CJS incondicionalmente.

### Buckets de clasificacion

| Bucket | Criterio |
|--------|----------|
| **Pasados** | Tests que corrieron y pasaron — control implementado y verificado |
| **Desactivados** | Tests con `.skip()` que tienen metadata — control temporalmente deshabilitado |
| **Migrados** | Tests con tag `Migrado` — control que antes aplicaba y ahora vive en otra capa |
| **No aplicables** | Tests con tag `N/A` — controles fuera del scope del SPA |

Cada bucket aparece como hoja separada en el Excel y como seccion filtrable en el HTML.

---

## PASO 4: Configurar Vitest

### `vitest.security.config.ts` (en la raiz del proyecto)

```typescript
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import path from 'node:path'

const reporterPath = path.resolve(
  __dirname,
  '.claude/skills/goes-security-vue/reporter',
)

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@security-reporter': reporterPath,
    },
  },
  test: {
    environment: 'jsdom',
    include: ['tests/security/**/*.security-html.spec.ts'],
    reporters: [
      'default',
      [path.join(reporterPath, 'html-reporter.cjs'), {
        outputPath: './reports/security/security-report.html',
      }],
    ],
  },
})
```

### Scripts npm

```json
{
  "scripts": {
    "test:unit": "vitest",
    "test:security": "vitest run --config vitest.security.config.ts",
    "test:e2e": "playwright test"
  }
}
```

### `.gitignore` — agregar si no existe

```
/coverage
/reports
/playwright-report
/test-results
```

`/reports` es regenerado en cada corrida — NO commitearlo.

### `eslint.config.js` — ignorar el reporter bundled + reports

El reporter es vendored 3rd party; no debe ser linteado. Agregar al array de `ignores`:

```js
ignores: [
  'dist', 'dist-ssr', 'coverage', 'node_modules', 'playwright-report',
  'reports',
  // Bundled reporter — vendored as-is, do not lint.
  'tests/security/reporter/**',
],
```

### Husky + lint-staged (recomendado)

Si el proyecto usa Husky, asegurar que `.husky/pre-commit` corra `lint-staged` con las reglas correctas para tests:

```js
// package.json
"lint-staged": {
  "*.{ts,vue,js}": ["eslint --fix", "prettier --write"],
  "*.{json,css,md,yml,yaml}": ["prettier --write"]
}
```

**Ojo con los `@ts-expect-error`** — la regla `@typescript-eslint/ban-ts-comment` requiere descripcion ≥3 chars (`// @ts-expect-error — reason here`). Sin descripcion, lint-staged aborta el commit.

---

## PASO 5: Generar tests

Para cada area del proyecto Vue crear los archivos siguiendo los 16 patterns. Cada pattern es un **template** con:

- Codigo TypeScript completo del spec real
- Lista de controles GOES + OWASP que cubre
- Severidad sugerida
- Notas de adaptacion al proyecto especifico

Estructura esperada:

```
tests/security/
├── reporter/                                    ← copiar bundled del skill
│   ├── html-reporter.cjs
│   └── metadata.ts
├── auth-store.security-html.spec.ts             ← pattern 01
├── router-guards.security-html.spec.ts          ← pattern 02
├── sanitize.security-html.spec.ts               ← pattern 03
├── api-client.security-html.spec.ts             ← pattern 04
├── refresh-coordinator.security-html.spec.ts    ← pattern 05
├── session-activity.security-html.spec.ts       ← pattern 06
├── auth-service-errors.security-html.spec.ts    ← pattern 07
├── permissions-matrix.security-html.spec.ts     ← pattern 08
├── not-applicable.security-html.spec.ts         ← pattern 09
├── build-source-audit.security-html.spec.ts     ← pattern 13
├── jwt-payload.security-html.spec.ts            ← pattern 14
├── api-client-403.security-html.spec.ts         ← pattern 15
└── idor-url-params.security-html.spec.ts        ← pattern 16

tests/e2e/
├── helpers.ts                                   ← shared helpers (_playwright-setup.md)
├── auth-flow.security.spec.ts                   ← pattern 10
├── rbac.security.spec.ts                        ← pattern 11
└── session.security.spec.ts                     ← pattern 12
```

### Metadata obligatoria por test

```typescript
const t = report()
t.epic('Access Control')              // area general
t.feature('Router guard')             // feature especifica
t.story('Unauth visit → /login')      // escenario concreto
t.severity('critical')                // blocker | critical | high | normal | minor
t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
t.descriptionHtml(
  '<p>Why this test exists, what attack it prevents.</p>' +
  '<p><strong>Reference:</strong> ' +
  '<a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/" target="_blank" rel="noopener">OWASP A01</a>.</p>',
)
```

### Estructura interna de cada test

```typescript
t.step('Prepare: mock the dependency / authenticate / setup state')
const input = { ... }
t.evidence('Input - attacker payload OR test scenario', input)

t.step('Execute: call the function under test')
const result = ...

t.step('Verify: assertions match the expected defense')
expect(result).toEqual(...)

t.evidence('Output - defense result', {
  resolved: ...,
  consequence: 'human-readable summary of what defended us',
})

await t.flush()
```

**Cada test DEBE incluir:**

1. `descriptionHtml` con `<a href="https://owasp.org/Top10/...">` link al control OWASP relevante
2. Al menos 1 `t.step('Prepare: ...')` y 1 `t.step('Execute/Verify: ...')`
3. Al menos 1 `t.evidence('Input - ...', payload)` con el payload del atacante O el escenario
4. Al menos 1 `t.evidence('Output - ...', result)` con el resultado de la defensa
5. `await t.flush()` al final — sin esto la metadata NO llega al reporte

### Si un control no aplica — documentar en `not-applicable.security-html.spec.ts`

NO omitir silenciosamente. Cada control que no aplica al SPA (password hashing, rate limiting, file uploads si no hay uploads, SQLi, CORS, DB encryption, security headers, webhooks, PCI) debe tener su entry en el spec N/A con:

- `control`: identificador GOES (ej. `GOES-R15`)
- `title`: descripcion del control
- `reason`: por que no aplica al SPA
- `mitigatedVector`: que vector de ataque mitigaria si aplicara
- `owasp`: referencia OWASP Top 10 o API top 10

Ver pattern 09.

---

## PASO 6: Generar artefactos del proyecto (NO solo tests)

El skill genera mas que tests. Para que el proyecto cumpla las practicas profesionales auditadas:

### `.env.example`

Una sola linea documentando la API:

```
VITE_API_URL=/api
```

> **Nota de seguridad**: TODA variable `VITE_*` queda **embebida en el bundle** de produccion — NO usar para secretos. Esto esta cubierto por el pattern 13 (`build-source-audit`).

### README profesional

El `README.md` del proyecto debe documentar (ver el README del propio skill como ejemplo):

- **Quick start** — clone, install, env, dev (4 pasos)
- **Variables de entorno** — tabla con `VITE_API_URL` y nota de seguridad
- **Estructura del repo** — arbol comentado de `src/` y `tests/`
- **Scripts** — tabla con `dev / build / type-check / lint / format / test:unit / test:security / test:e2e`
- **Autenticacion y sesion** — explicacion del esquema hibrido (access in-memory, refresh httpOnly, refresh coordinator, idle scheduler, open-redirect guard) con links a los archivos del codigo
- **RBAC** — tabla `perfil × roles × capacidades` apuntando al PERMISOS matrix spec
- **Credenciales sembradas** — tabla con los 3 usuarios del seeder (admin / tecnico / consulta) — solo para testing local
- **Suite de seguridad** — tabla con los 9 specs y los controles que cubre cada uno
- **E2E Playwright** — tabla con los 3 specs + nota del skip-if-no-backend
- **Calidad y hooks** — Husky + lint-staged + type-check + .gitignore
- **IDE recomendado** — VSCode + Volar
- **Companion repos** — links al backend + skills

---

## PASO 7: Verificacion

Despues de generar todos los archivos:

1. Ejecutar `npm run test:security` — todos los tests deben pasar y los reportes deben generarse
2. Si hay errores de ESLint, corregirlos (`@ts-expect-error` con descripcion, `unused-vars` con `^_` prefix, no-explicit-any)
3. Verificar que se generaron AMBOS artefactos:
   - `reports/security/security-report.html`
   - `reports/security/security-report.xlsx`
4. Mostrar resumen: cuantos tests generados, cuantos items del checklist cubiertos, cuantos OWASP cubiertos, distribucion por bucket
5. Si se generaron E2E: `npm run test:e2e` debe pasar o skipear limpio si el backend no esta corriendo

---

## PASO 8: Reglas de hardening del proyecto Vue

Estas son lecciones aprendidas del audit del SPA real. Aplicarlas al generar/revisar codigo:

### 8.1 — NUNCA usar emojis para iconos UI

Politica: TODO icono UI usa **Lucide** (`lucide-vue-next`). Razones:

- Los emojis renderizan inconsistentemente entre OS (cloud ☁ aparece como tofu en Linux/Windows sin fuente emoji)
- Lucide hereda el color del padre — mejor integracion con tema claro/oscuro
- Lucide es vector — escala perfecto en cualquier resolucion

Reemplazos comunes:

| Emoji | Lucide |
|-------|--------|
| ☁ Cloud | `<Cloud />` |
| 🏢 Building | `<Building2 />` |
| ⚠️ Warning | `<AlertTriangle />` o `<AlertCircle />` |
| ✅ Check | `<CheckCircle2 />` |
| 🔄 Refresh | `<RefreshCw />` |
| 📅 Calendar | `<Calendar />` |
| 🔒 Lock | `<Lock />` |
| 🚫 Ban | `<Ban />` |
| ⌛ Hourglass | `<Clock />` |
| ✏ Pencil | `<Pencil />` |
| 🔴/🟡/🟢 dots | `<Circle :style="{ color, fill: color }" />` |
| 🎓 Graduation | `<GraduationCap />` |
| 🗄️ Storage | `<Database />` |
| 📊 Chart | `<BarChart3 />` |
| ⚙ Settings | `<Settings />` |
| ➕ Plus | `<Plus />` |
| 🗑 Trash | `<Trash2 />` |

Para `<select><option>` mantener el label como texto puro (los browsers strippean HTML adentro de `<option>`). El icono va al lado del select como badge separado.

### 8.2 — Login con card design + dark mode

El `<input type="password">` debe tener `:type="showPassword ? 'text' : 'password'"` con un boton `<Eye />`/`<EyeOff />` para mostrar/ocultar. Ojo: el spec de autocomplete debe usar `id="password"` como anchor, NO `type="password"` (porque ahora es dinamico).

El layout debe ser una card con:

- Brand icon (`ShieldCheck`) en cuadro 48px
- Titulo + subtitulo
- Inputs con leading icons (`Mail`, `Lock`)
- Error como banner (`AlertCircle` + `border-danger/30 bg-danger/10`)
- Submit con `Loader2` durante request + `LogIn` idle
- Tokens semanticos: `bg-surface`, `text-foreground`, `border-border`, `text-danger`, etc.

### 8.3 — ThemeToggle con variant prop

El toggle de dark/light mode necesita DOS variantes para que el contraste funcione en todos los contextos:

- `variant="topbar"`: para topbars con fondo navy hardcoded — usa paleta `white/XX`
- `variant="default"`: para headers sobre `bg-background` — usa tokens semanticos (`border-border`, `text-muted-foreground`)

Sin esto, el toggle queda invisible cuando se usa fuera del topbar privado.

### 8.4 — Paginacion + busqueda en catalogos

Para catalogos chicos (< pocos cientos de filas) que ya estan cargados completos en memoria via `fetchCatalogs()`, hacer **paginacion + busqueda client-side**:

```typescript
const PAGE_SIZE = 8
const searchDraft = ref('')
const page = ref(1)

watch(searchDraft, () => { page.value = 1 })  // reset on query change

const filtered = computed(() =>
  searchDraft.value === '' ? full :
    full.filter(r => r.code.toLowerCase().includes(searchDraft.value.toLowerCase())))

const totalPages = computed(() => Math.max(1, Math.ceil(filtered.value.length / PAGE_SIZE)))
const paged = computed(() => filtered.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE))
```

Cero round-trips por keystroke. Si el catalogo crece a miles, migrar a server-side con los endpoints BE que ya soportan `page/limit/search`.

### 8.5 — Brand y nombre del sistema

Si el sistema tiene un nombre de marca (ej: SYSTEC, MINEDUCYT), centralizar en:

- `<title>` en `index.html`
- Header del PublicLayout (login)
- Header del PrivateLayout (topbar) + drawer mobile
- Subtitulo del LoginView
- README.md

NO hardcodear el nombre en cada componente. La marca puede vivir en una constante exportada desde `@/app/config/branding.ts` para facilitar rebrands.

### 8.6 — Backend logout publico

El endpoint `POST /auth/logout` en GOES backend es **publico a proposito** (sin guard JWT) para que un usuario con access token expirado pueda cerrar sesion limpiamente. El SPA debe usar `_skipRefresh: true` en el request a `/logout` para que el interceptor no intente refrescar el token cuando el server ya borro el cookie.

### 8.7 — N/A spec exhaustivo

Para que el reporte sea util al auditor, el spec `not-applicable` debe documentar **explicitamente** cada control que no aplica con motivo + vector mitigado. Auditor copia/pega cada fila del Excel directo al anexo regulatorio.

### 8.8 — `descriptionHtml` SIEMPRE con OWASP link

Cada test debe terminar su `descriptionHtml` con:

```html
<p><strong>Reference:</strong>
<a href="https://owasp.org/Top10/A0X_2021-..." target="_blank" rel="noopener">OWASP AXX</a>.</p>
```

Asi el reporte HTML linkea directo a la documentacion canonica del control. El reporter NO genera el link automaticamente — debe ir manual en el `descriptionHtml`.

---

## PATTERNS INCLUIDOS

Ver `references/test-patterns/` para el codigo completo de cada pattern.

### Unit tests (Vitest)

| # | Archivo | Cubre | OWASP |
|---|---------|-------|-------|
| 01 | `01-auth-store-rbac.md` | R9, R34, VF7 — Pinia store, PERMISOS, clearSession, fail-closed | A01 |
| 02 | `02-router-guards.md` | R9, R21, R24, VF8 — guards: auth + RBAC + parent chain | A01 |
| 03 | `03-client-sanitize.md` | R5, R11, VF1 — sanitize.ts, firstUnsafeKey, XSS regex | A03 |
| 04 | `04-api-client-defaults.md` | R40, VF3 — withCredentials, timeout, Bearer | A04, A07 |
| 05 | `05-refresh-coordinator.md` | R32 — single-flight + cooldown + max attempts | A07 |
| 06 | `06-session-activity.md` | R35, R40 — activity tracker + idle scheduler | A04, A07 |
| 07 | `07-auth-service-errors.md` | R8, R14, VF12 — generic errors + open-redirect + storage audit | A01, A02, A07 |
| 08 | `08-permissions-matrix-vhtml-autocomplete.md` | R9, R11, R14, VF1, VF11 — matriz PERMISOS + sweep v-html + autocomplete | A01, A03, A07 |
| 09 | `09-not-applicable.md` | scope boundaries — server-side controls out of scope | — |
| 13 | `13-build-source-audit.md` | R3, R10, VF6, VF10 — console.log + hardcoded secrets + VITE_* | A05, A09 |
| 14 | `14-jwt-payload-safety.md` | R20 — no PII in JWT claims | A02 |
| 15 | `15-interceptor-403-handling.md` | VF5 — 403 does not refresh / does not clear session | A01 |
| 16 | `16-idor-url-params.md` | R23 — URL params untrusted; self-only routes cross-check | A01 |

### E2E tests (Playwright)

| # | Archivo | Cubre | OWASP |
|---|---------|-------|-------|
| 10 | `10-e2e-auth-flow.md` | R8, R14, R42, VF12 — wrong creds / happy path / redirect / storage | A01, A07 |
| 11 | `11-e2e-rbac.md` | R9, R24, R34 — profile matrix x route matrix | A01 |
| 12 | `12-e2e-session-lifecycle.md` | R35, R40, VF4 — unauth redirect + logout cookie revocation | A04, A07 |

### Support files

| Archivo | Contenido |
|---------|-----------|
| `_setup.md` | vitest.security.config.ts + scripts + spec shape |
| `_severity-guide.md` | Como asignar blocker/critical/high/normal/minor |
| `_playwright-setup.md` | playwright.config.ts + helpers.ts + skip-if-no-backend |

---

## NOTAS IMPORTANTES PARA LA IA

1. **NUNCA generar tests vacios o placeholder** — cada test debe tener assertions reales contra el codigo del proyecto.
2. **Analizar el codigo real** antes de escribir tests. Leer el archivo `.ts` / `.vue` y entender los metodos, stores, guards y logica.
3. **Si un item del checklist no aplica** al proyecto actual, generar entry en `not-applicable.security-html.spec.ts` con motivo y vector. Nunca omitir silenciosamente.
4. **Priorizar tests de seguridad** sobre tests funcionales.
5. **Los comentarios del codigo van en ingles** (ASCII puro). Los `descriptionHtml` del reporter pueden ir en ingles o espanol segun la preferencia del equipo, pero sean consistentes.
6. **Respetar el `tsconfig.json`** del proyecto.
7. **Cada test debe ser independiente** — `beforeEach(() => setActivePinia(createPinia()))`.
8. **Usar `vi.mock`** para side-effects transversales (session-scheduler, refresh-coordinator, activity-tracker) en specs que no los testean directamente — sino la store dispara timers reales que ensucian stderr.
9. **`@ts-expect-error` requiere descripcion** (`// @ts-expect-error — wrong-case role, not in the Role union.`) para pasar lint-staged.
10. **Cada test DEBE terminar con `await t.flush()`**.
11. **NO instalar Allure ni Java**.
12. **El reporter `html-reporter.cjs` DEBE ser JavaScript puro** — Vitest lo carga con `require()`.
13. **Specs unit terminan en `.security-html.spec.ts`**; E2E en `.security.spec.ts` dentro de `tests/e2e/`.
14. **E2E requieren backend real** — el helper `backendIsUp()` skipea el suite automaticamente si `/api/auth/session` no responde.
15. **Reemplazar emojis UI por Lucide** sistemicamente — politica del proyecto (PASO 8.1).
16. **Cada `t.evidence('Input -' / 'Output -')`** documenta el payload y la respuesta de defensa. Sin esto el reporte queda sin valor de auditoria.
17. **Cada `descriptionHtml` debe linkear a owasp.org** con `<a href target="_blank" rel="noopener">`.
