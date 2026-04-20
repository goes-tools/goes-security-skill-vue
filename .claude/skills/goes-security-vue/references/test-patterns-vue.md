# Test Patterns — Vue.js Frontend Security

Exact patterns to use when generating tests. Copy and adapt to the real component/composable.

## Basic setup for each spec file

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, shallowMount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import { report } from './reporter/metadata';

describe('ComponentName', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  // ... tests ...
});
```

## Pattern 1: PENTEST — XSS via v-html

```typescript
it('PENTEST: should sanitize user input before rendering with v-html', async () => {
  const t = report();
  t.epic('Security');
  t.feature('XSS Prevention');
  t.story('Sanitize dynamic HTML content to prevent script injection');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A03', 'GOES Checklist R5', 'GOES Checklist VF1');

  const xssPayloads = [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert("xss")>',
    '<svg onload=alert("xss")>',
    'javascript:alert("xss")',
    '<iframe src="javascript:alert(1)">',
  ];

  t.parameter('payloads', xssPayloads.length.toString());

  for (const payload of xssPayloads) {
    t.step(`Test payload: ${payload.substring(0, 30)}...`);
    const wrapper = mount(MyComponent, {
      props: { content: payload },
    });

    const html = wrapper.html();
    expect(html).not.toContain('<script>');
    expect(html).not.toContain('onerror');
    expect(html).not.toContain('onload');
    expect(html).not.toContain('javascript:');
  }

  t.evidence('XSS payloads tested (input)', { payloads: xssPayloads });
  t.evidence('Defense result (output)', {
    allPayloadsBlocked: true,
    sanitizer: 'DOMPurify or equivalent',
  });

  await t.flush();
});
```

## Pattern 2: Route Guard — Authentication Required

```typescript
it('should redirect unauthenticated users to login page', async () => {
  const t = report();
  t.epic('Authentication');
  t.feature('Route Guard Protection');
  t.story('Redirect to login when accessing protected route without auth');
  t.severity('blocker');
  t.tag('Auth', 'OWASP A01', 'GOES Checklist R21', 'GOES Checklist VF8');

  t.parameter('route', '/dashboard');
  t.parameter('authenticated', 'false');

  t.step('Prepare: clear auth state');
  const authStore = useAuthStore();
  authStore.$reset();

  t.step('Execute: navigate to protected route');
  await router.push('/dashboard');

  t.step('Verify: redirected to login');
  expect(router.currentRoute.value.path).toBe('/login');
  expect(router.currentRoute.value.query.redirect).toBe('/dashboard');

  t.evidence('Navigation result (output)', {
    attempted: '/dashboard',
    redirectedTo: '/login',
    reason: 'No valid authentication token',
  });

  await t.flush();
});
```

## Pattern 3: Route Guard — Role-Based Access

```typescript
it('PENTEST: should block non-admin users from accessing admin routes', async () => {
  const t = report();
  t.epic('Authentication');
  t.feature('Role-Based Access Control');
  t.story('Regular user cannot access admin panel');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A01', 'GOES Checklist R24', 'GOES Checklist R34');

  t.parameter('user_role', 'USER');
  t.parameter('required_role', 'ADMIN');
  t.parameter('route', '/admin/users');

  t.step('Prepare: set user as regular USER');
  const authStore = useAuthStore();
  authStore.user = { id: '1', role: 'USER' };
  authStore.token = 'valid-token';

  t.evidence('Attacker state (input)', {
    userId: '1', role: 'USER', attemptedRoute: '/admin/users',
  });

  t.step('Execute: regular user tries to access admin route');
  await router.push('/admin/users');

  t.step('Verify: access denied, redirected to forbidden or home');
  expect(router.currentRoute.value.path).not.toBe('/admin/users');

  t.evidence('Defense result (output)', {
    accessDenied: true,
    reason: 'Insufficient role: USER cannot access ADMIN routes',
  });

  await t.flush();
});
```

## Pattern 4: PENTEST — Token Storage Security

```typescript
it('PENTEST: should NOT store auth tokens in localStorage or sessionStorage', async () => {
  const t = report();
  t.epic('Security');
  t.feature('Secure Token Storage');
  t.story('Tokens must be in httpOnly cookies, not browser storage');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A02', 'GOES Checklist R42');

  t.step('Prepare: spy on localStorage and sessionStorage');
  vi.spyOn(Storage.prototype, 'setItem');

  t.step('Execute: perform login flow');
  const authStore = useAuthStore();
  await authStore.login({ email: 'test@test.com', password: 'password' });

  t.step('Verify: no tokens in localStorage');
  const localStorageCalls = vi.mocked(localStorage.setItem).mock.calls;
  const tokenKeys = localStorageCalls.filter(([key]) =>
    key.toLowerCase().includes('token') ||
    key.toLowerCase().includes('jwt') ||
    key.toLowerCase().includes('auth')
  );
  expect(tokenKeys).toHaveLength(0);

  t.step('Verify: no tokens in sessionStorage');
  const sessionCalls = vi.mocked(sessionStorage.setItem).mock.calls;
  const sessionTokenKeys = sessionCalls.filter(([key]) =>
    key.toLowerCase().includes('token') ||
    key.toLowerCase().includes('jwt') ||
    key.toLowerCase().includes('auth')
  );
  expect(sessionTokenKeys).toHaveLength(0);

  t.evidence('Defense result (output)', {
    localStorageTokens: 0,
    sessionStorageTokens: 0,
    storageMethod: 'httpOnly cookie or in-memory only',
  });

  await t.flush();
});
```

## Pattern 5: API Interceptor — 401 Handling

```typescript
it('should redirect to login and clear tokens on 401 response', async () => {
  const t = report();
  t.epic('Authentication');
  t.feature('401 Error Handling');
  t.story('Clear auth state and redirect on unauthorized response');
  t.severity('critical');
  t.tag('Auth', 'OWASP A07', 'GOES Checklist VF4');

  t.step('Prepare: mock API to return 401');
  vi.mocked(api.get).mockRejectedValue({
    response: { status: 401, data: { message: 'Token expired' } },
  });

  const authStore = useAuthStore();

  t.step('Execute: make authenticated API call');
  try {
    await authStore.fetchProfile();
  } catch {
    // Expected to fail
  }

  t.step('Verify: auth state cleared');
  expect(authStore.token).toBeNull();
  expect(authStore.user).toBeNull();

  t.step('Verify: redirected to login');
  expect(router.currentRoute.value.path).toBe('/login');

  t.evidence('Defense result (output)', {
    tokenCleared: true,
    userCleared: true,
    redirectedTo: '/login',
  });

  await t.flush();
});
```

## Pattern 6: Environment Variable Security

```typescript
it('PENTEST: should not expose secrets in VITE_ environment variables', async () => {
  const t = report();
  t.epic('Security');
  t.feature('Environment Variable Security');
  t.story('No secrets or API keys in client-accessible env vars');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A05', 'GOES Checklist R3', 'GOES Checklist VF6', 'GOES Checklist VF10');

  t.step('Verify: no secrets in import.meta.env');
  const envKeys = Object.keys(import.meta.env);
  const suspiciousKeys = envKeys.filter((key) =>
    key.match(/SECRET|PASSWORD|PRIVATE|KEY|TOKEN|API_KEY/i) &&
    key.startsWith('VITE_')
  );
  expect(suspiciousKeys).toHaveLength(0);

  t.evidence('Env vars audited (output)', {
    totalViteVars: Object.keys(import.meta.env).filter(k => k.startsWith('VITE_')).length,
    secretsFound: 0,
  });

  await t.flush();
});
```

## Pattern 7: Store Cleanup on Logout

```typescript
it('should clear all sensitive data from store on logout', async () => {
  const t = report();
  t.epic('Security');
  t.feature('Store Cleanup on Logout');
  t.story('No sensitive data remains in Pinia store after logout');
  t.severity('critical');
  t.tag('Auth', 'OWASP A02', 'GOES Checklist VF7');

  const authStore = useAuthStore();

  t.step('Prepare: simulate logged-in state');
  authStore.token = 'valid-token';
  authStore.user = { id: '1', email: 'user@test.com', role: 'ADMIN' };

  t.step('Execute: logout');
  await authStore.logout();

  t.step('Verify: all sensitive data cleared');
  expect(authStore.token).toBeNull();
  expect(authStore.user).toBeNull();
  expect(authStore.isAuthenticated).toBe(false);

  t.evidence('Store state after logout (output)', {
    token: authStore.token,
    user: authStore.user,
    isAuthenticated: authStore.isAuthenticated,
  });

  await t.flush();
});
```

## Pattern 8: Console.log in Production

```typescript
it('should not have console.log calls in production components', async () => {
  const t = report();
  t.epic('Security');
  t.feature('Log Exposure Prevention');
  t.story('No console.log statements in production code');
  t.severity('critical');
  t.tag('Config', 'OWASP A09', 'GOES Checklist R10');

  t.step('Verify: console.log spy not called during render');
  const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  const wrapper = mount(MyComponent);
  // Trigger component lifecycle
  await wrapper.vm.$nextTick();

  expect(consoleSpy).not.toHaveBeenCalled();
  consoleSpy.mockRestore();

  t.evidence('Result (output)', {
    consoleLogCalls: 0,
    status: 'No sensitive logs exposed',
  });

  await t.flush();
});
```

## Severities — Assignment Guide

| Severity | When to use | Example |
|----------|-------------|---------|
| blocker | If it fails, the app is insecure | XSS possible, route guard bypassed, tokens in localStorage |
| critical | Critical functionality compromised | No 401 handling, console.log in prod, secrets in env |
| normal | Standard functionality | 404 page, input format validation |
| minor | Non-critical edge cases | CSS-only issues, cosmetic error messages |
| trivial | Cosmetic | Response format |
