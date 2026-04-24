---
name: goes-security-testing-vue
description: "Genera tests de seguridad para proyectos Vue 3 + Vitest + Playwright con un Custom HTML + Excel Reporter (sin Java ni Allure) cubriendo el Checklist de Ciberseguridad GOES (items frontend), OWASP Top 10 y controles especificos de SPA (VF1-VF12). Configura Vitest + custom reporter y crea specs completas con evidencia JSON, trazabilidad regulatoria y clasificacion por epicas. El reporte incluye sidebar Epic-Feature-Story, graficos SVG, tema oscuro, busqueda y buckets (Pasados / Desactivados / Migrados / No aplicables). Activar cuando el usuario pida: tests de seguridad frontend, tests de seguridad Vue, checklist GOES frontend, pentest tests frontend, security specs Vue, reporte de seguridad HTML o Excel para Vue, security report frontend, o cualquier variante."
---

# GOES Security Testing — Skill para Vue 3 + Vitest + Custom HTML + Excel Reporter

## Resumen

Este skill genera tests de seguridad profesionales para proyectos **Vue 3 + Vitest** (unit) y **Playwright** (E2E) con un **Custom HTML + Excel Reporter** (sin Java, sin Allure). Cubre los items frontend del Checklist de Ciberseguridad GOES, **OWASP Top 10** y controles especificos de SPA (VF1-VF12).

El reporter produce DOS artefactos autocontenidos:

- **HTML** (`reports/security/security-report.html`)
  - Sidebar con navegacion por Epic > Feature > Story
  - Modal de detalle con severity badges, tags, steps y evidencia JSON con syntax highlighting
  - Graficos SVG (pie de pass/fail, barras por severity, donut OWASP)
  - Buckets: Pasados / Desactivados / Migrados / No aplicables
  - Tema oscuro, busqueda en tiempo real
- **Excel** (`reports/security/security-report.xlsx`)
  - Una hoja por bucket, una fila por test con todos los campos de metadata y tags
  - Ideal como anexo de auditoria regulatoria

---

## PASO 1: Analizar el proyecto

Antes de generar codigo, analizar la estructura real del proyecto Vue:

```
1. Leer package.json:
   - Framework (vue 3)
   - Test runner (vitest — si no existe, instalarlo)
   - "type": "module" — si esta, el reporter DEBE cargarse como .cjs
   - Dependencias de auth: pinia, vue-router, axios, @tanstack/vue-query, etc.
   - Package manager: pnpm-lock.yaml | yarn.lock | package-lock.json

2. Listar estructura:
   - Glob src/views/**/*.vue  o  src/pages/**/*.vue — vistas/paginas
   - Glob src/components/**/*.vue — componentes
   - Glob src/router/**/*.ts — rutas y guards
   - Glob src/stores/**/*.ts  o  src/features/**/stores/**/*.ts — stores Pinia
   - Glob src/composables/**/*.ts — composables (auth, api, activity, idle)
   - Glob src/lib/**/*.ts  o  src/services/**/*.ts — api client, interceptors, helpers

3. Identificar que ya existe:
   - Archivos .spec.ts / .test.ts existentes
   - Configuracion de Vitest actual
   - Playwright configurado? (playwright.config.ts)
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

**NO instalar Allure, allure-vitest ni allure-commandline.** Este sistema usa un reporter custom puro Node.js que no necesita Java ni dependencias externas de reporte.

---

## PASO 3: Configurar el custom reporter

Este skill incluye el reporter bundled en `.claude/skills/goes-security-vue/reporter/`. **NO copiar los archivos** — referenciarlos directamente para evitar duplicados.

El reporter consiste en dos archivos:

- **`reporter/html-reporter.cjs`** — Vitest custom reporter (JavaScript puro, ~1900 lineas). Soporta Vitest v4 (`onTestRunEnd`) con fallback para v3 (`onFinished`) y Jest legacy (`onRunComplete`). Lee metadata JSON temporales, cruza con resultados, genera HTML + Excel autocontenidos con sidebar, charts SVG, dark theme, busqueda y buckets.
- **`reporter/metadata.ts`** — Collector de metadata. Exporta `report()` y `AllureCompat`. Cada test registra epic, feature, story, severity, tags, steps, evidencia. Se escribe a archivos JSON temporales via `flush()`.

**NO modificar los archivos del reporter.** Estan listos para usar.

### Por que `.cjs` y no `.js`?

Proyectos generados con `create-vue`/Vite llevan `"type": "module"` en `package.json`. Bajo ese modo Node trata los `.js` como ESM; Jest/Vitest custom reporters son CommonJS. La extension `.cjs` fuerza parseo CJS incondicionalmente.

### Buckets de clasificacion

El reporter clasifica automaticamente cada test en uno de cuatro buckets segun sus tags:

| Bucket | Criterio | Cuando usarlo |
|--------|----------|---------------|
| **Pasados** | Tests que corrieron y pasaron | Control implementado y verificado |
| **Desactivados** | Tests con `.skip()` que tienen metadata | Control temporalmente deshabilitado (ej: BE caido, feature flag apagado) |
| **Migrados** | Tests con tag `Migrado` | Control que antes aplicaba y ahora vive en otra capa |
| **No aplicables** | Tests con tag `N/A` | Controles fuera del scope del SPA (ej: password hashing es server-side) |

Cada bucket aparece como una hoja separada en el Excel y como una seccion filtrable en el HTML.

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

El alias `@security-reporter` permite que los specs importen metadata limpiamente:

```typescript
import { report } from '@security-reporter/metadata'
```

### Scripts npm (agregar a `package.json`)

```json
{
  "scripts": {
    "test:security": "vitest run --config vitest.security.config.ts",
    "test:e2e": "playwright test"
  }
}
```

Para generar el reporte:

```bash
npm run test:security
# HTML:  reports/security/security-report.html
# Excel: reports/security/security-report.xlsx
```

Ambos archivos se regeneran en cada corrida. El HTML es autocontenido (se puede abrir sin servidor). El Excel incluye una hoja por bucket y es ideal para anexos de auditoria.

---

## PASO 5: Crear archivos de soporte

### `.gitignore` — agregar si no existen

```
/coverage
/reports
```

### `eslint.config.ts` — override para archivos de test

```ts
// Dentro del array de configuracion, agregar:
{
  files: ['**/*.spec.ts', '**/*.e2e.spec.ts', 'tests/**/*.ts'],
  rules: {
    '@typescript-eslint/no-unsafe-assignment': 'off',
    '@typescript-eslint/no-unsafe-member-access': 'off',
    '@typescript-eslint/no-unsafe-call': 'off',
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/require-await': 'off',
  },
}
```

---

## PASO 6: Generar tests

Para CADA area del proyecto Vue crear los archivos `.security-html.spec.ts` siguiendo los patterns de este skill. Los patterns son **ejemplos de referencia**: hay que adaptarlos leyendo el codigo real del proyecto.

Estructura esperada:

```
tests/security/
├── auth-store.security-html.spec.ts            ← pattern 01
├── router-guards.security-html.spec.ts         ← pattern 02
├── sanitize.security-html.spec.ts              ← pattern 03
├── api-client.security-html.spec.ts            ← pattern 04
├── refresh-coordinator.security-html.spec.ts   ← pattern 05
├── session-activity.security-html.spec.ts      ← pattern 06
├── auth-service-errors.security-html.spec.ts   ← pattern 07
├── permissions-matrix.security-html.spec.ts    ← pattern 08 (PERMISOS + v-html + autocomplete)
├── not-applicable.security-html.spec.ts        ← pattern 09 (scope boundaries)
├── build-source-audit.security-html.spec.ts    ← pattern 13 (console.log / secrets / VITE_*)
├── jwt-payload.security-html.spec.ts           ← pattern 14
├── api-client-403.security-html.spec.ts        ← pattern 15
└── idor-url-params.security-html.spec.ts       ← pattern 16

tests/e2e/
├── helpers.ts                                  ← shared helpers (_playwright-setup.md)
├── auth-flow.security.spec.ts                  ← pattern 10
├── rbac.security.spec.ts                       ← pattern 11
└── session.security.spec.ts                    ← pattern 12
```

### Metadata obligatoria por test

```typescript
const t = report()
t.epic('Access Control')              // area general
t.feature('Router guard')             // feature especifica
t.story('Unauth visit → /login')      // escenario concreto
t.severity('critical')                // blocker | critical | high | normal | minor
t.tag('Pentest', 'OWASP-A01', 'GOES-R9')
t.descriptionHtml('<p>Why this test exists...</p>')
```

### Regla critica — `flush()`

Cada test DEBE terminar con `await t.flush()` (o `await allure.flush()` si usa `AllureCompat`). Sin flush, la metadata no se escribe y el reporte no tendra los detalles del test.

### Si un control no aplica — documentar en `not-applicable.security-html.spec.ts`

No omitir silenciosamente. Cada control que no aplica al SPA (password hashing, rate limiting, file uploads si no hay uploads, SQLi, CORS, DB encryption, security headers, webhooks, PCI) debe tener su entry en el spec N/A con el motivo y el vector que mitigaria si aplicara. Ver `references/test-patterns/09-not-applicable.md`.

---

## PASO 7: Verificacion

Despues de generar todos los archivos:

1. Ejecutar `npm run test:security` para verificar que todos los tests pasan y los reportes se generan
2. Si hay errores de ESLint, corregirlos (especialmente `require-await` y `no-explicit-any` en archivos de test)
3. Verificar que se generaron AMBOS artefactos:
   - `reports/security/security-report.html`
   - `reports/security/security-report.xlsx`
4. Mostrar resumen: cuantos tests generados, cuantos items del checklist cubiertos, cuantos OWASP cubiertos, distribucion por bucket (pasados / desactivados / migrados / no aplicables)
5. Si se generaron E2E: `npm run test:e2e` debe pasar o skipear limpio si el backend no esta corriendo

---

## PATTERNS INCLUIDOS

Ver `references/test-patterns/` para el codigo completo de cada pattern. Cada archivo contiene el spec listo para adaptar al proyecto real.

### Unit tests (Vitest)

| # | Archivo | Cubre |
|---|---------|-------|
| 01 | `01-auth-store-rbac.md` | R9, R34, VF7 — Pinia store invariants + PERMISOS + clearSession |
| 02 | `02-router-guards.md` | R9, R21, R24, VF8 — guards: auth + RBAC + hydration + parent chain |
| 03 | `03-client-sanitize.md` | R5, R11, VF1 — sanitize.ts, firstUnsafeKey, XSS regex |
| 04 | `04-api-client-defaults.md` | R40, VF3 — axios defaults: withCredentials, timeout, Bearer |
| 05 | `05-refresh-coordinator.md` | R32 — single-flight + cooldown + max attempts |
| 06 | `06-session-activity.md` | R35, R40 — activity tracker + idle scheduler |
| 07 | `07-auth-service-errors.md` | R8, R14, VF12 — generic errors + open-redirect + storage audit |
| 08 | `08-permissions-matrix-vhtml-autocomplete.md` | R9, R11, R14, VF1, VF11 — PERMISOS matrix + v-html sweep + autocomplete hygiene |
| 09 | `09-not-applicable.md` | scope boundaries — server-side controls out of scope |
| 13 | `13-build-source-audit.md` | R3, R10, VF6, VF10 — console.log + hardcoded secrets + VITE_* |
| 14 | `14-jwt-payload-safety.md` | R20 — no PII in JWT claims |
| 15 | `15-interceptor-403-handling.md` | VF5 — 403 does not refresh / does not clear session |
| 16 | `16-idor-url-params.md` | R23 — URL params are untrusted; self-only routes cross-check |

### E2E tests (Playwright)

| # | Archivo | Cubre |
|---|---------|-------|
| 10 | `10-e2e-auth-flow.md` | R8, R14, R42, VF12 — wrong creds / happy path / redirect / storage |
| 11 | `11-e2e-rbac.md` | R9, R24, R34 — profile matrix x route matrix |
| 12 | `12-e2e-session-lifecycle.md` | R35, R40, VF4 — unauth redirect + logout cookie revocation |

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
3. **Si un item del checklist no aplica** al proyecto actual (ej: el SPA no maneja uploads, no tiene JWT decodificado client-side), generar entry en `not-applicable.security-html.spec.ts` con motivo y vector. Nunca omitir silenciosamente.
4. **Priorizar tests de seguridad** sobre tests funcionales.
5. **Los comentarios del codigo van en ingles** (ASCII puro). Los `descriptionHtml` del reporter pueden ir en ingles o espanol segun la preferencia del equipo, pero sean consistentes.
6. **Respetar el `tsconfig.json`** del proyecto. Si `strict: true` esta, mantenerlo.
7. **Cada test debe ser independiente** — no depender del orden de ejecucion ni de estado compartido. Usar `beforeEach` con `createPinia()` fresh.
8. **Usar `vi.mock`** para side-effects transversales (session-scheduler, refresh-coordinator, activity-tracker) en specs que no los testean directamente.
9. **Cada test DEBE terminar con `await t.flush()`** — sin esto la metadata no llega al reporte.
10. **NO instalar Allure ni Java** — reporter custom puro Node.js.
11. **El reporter `html-reporter.cjs` DEBE ser JavaScript puro** — Vitest lo carga con `require()`. Si es necesario modificarlo, no convertirlo a TypeScript.
12. **Los specs de unit deben terminar en `.security-html.spec.ts`**; los de E2E en `.security.spec.ts` dentro de `tests/e2e/`.
13. **E2E requieren backend real** — el helper `backendIsUp()` skipea el suite automaticamente si `/api/auth/session` no responde.
