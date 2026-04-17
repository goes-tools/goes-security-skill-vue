# Test Patterns — Vue.js Frontend Security

Exact patterns to use when generating tests. Copy and adapt to the real component/composable.

## Basic setup for each spec file

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, shallowMount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import * as allure from 'allure-js-commons';

// Evidence helper — define ONCE per file
async function attach(name: string, data: unknown) {
  await allure.attachment(name, JSON.stringify(data, null, 2), {
    contentType: 'application/json',
  });
}

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
  await allure.epic('Security');
  await allure.feature('XSS Prevention');
  await allure.story('Sanitize dynamic HTML content to prevent script injection');
  await allure.severity('blocker');
  await allure.tag('Pentest');
  await allure.tag('OWASP A03');
  await allure.tag('GOES Checklist R5');
  await allure.tag('GOES Checklist VF1');
  await allure.description(
    '## Vulnerability prevented\n' +
    '**Cross-Site Scripting (XSS)** — An attacker injects malicious\n' +
    'scripts through user input that gets rendered via v-html.\n\n' +
    '## Defense implemented\n' +
    'All user-provided content rendered with v-html must be sanitized\n' +
    'using DOMPurify or equivalent before rendering.\n\n' +
    '## Reference\n' +
    'OWASP A03:2021 — Injection',
  );

  const xssPayloads = [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert("xss")>',
    '<svg onload=alert("xss")>',
    'javascript:alert("xss")',
    '<iframe src="javascript:alert(1)">',
  ];

  await allure.parameter('payloads', xssPayloads.length.toString());

  for (const payload of xssPayloads) {
    await allure.step(`Test payload: ${payload.substring(0, 30)}...`, async () => {
      const wrapper = mount(MyComponent, {
        props: { content: payload },
      });

      const html = wrapper.html();
      expect(html).not.toContain('<script>');
      expect(html).not.toContain('onerror');
      expect(html).not.toContain('onload');
      expect(html).not.toContain('javascript:');
    });
  }

  await attach('XSS payloads tested (input)', { payloads: xssPayloads });
  await attach('Defense result (output)', {
    allPayloadsBlocked: true,
    sanitizer: 'DOMPurify or equivalent',
  });
});
```

## Pattern 2: Route Guard — Authentication Required

```typescript
it('should redirect unauthenticated users to login page', async () => {
  await allure.epic('Authentication');
  await allure.feature('Route Guard Protection');
  await allure.story('Redirect to login when accessing protected route without auth');
  await allure.severity('blocker');
  await allure.tag('Auth');
  await allure.tag('OWASP A01');
  await allure.tag('GOES Checklist R21');
  await allure.tag('GOES Checklist VF8');
  await allure.description(
    '## Objective\n' +
    'Verify that navigation guards prevent unauthenticated users\n' +
    'from accessing protected routes.\n\n' +
    '## Expected behavior\n' +
    '- Unauthenticated user trying to access /dashboard\n' +
    '- Guard detects no valid token\n' +
    '- Redirects to /login with return URL',
  );

  await allure.parameter('route', '/dashboard');
  await allure.parameter('authenticated', 'false');

  await allure.step('Prepare: clear auth state', async () => {
    const authStore = useAuthStore();
    authStore.$reset();
  });

  await allure.step('Execute: navigate to protected route', async () => {
    await router.push('/dashboard');
  });

  await allure.step('Verify: redirected to login', async () => {
    expect(router.currentRoute.value.path).toBe('/login');
    expect(router.currentRoute.value.query.redirect).toBe('/dashboard');
  });

  await attach('Navigation result (output)', {
    attempted: '/dashboard',
    redirectedTo: '/login',
    reason: 'No valid authentication token',
  });
});
```

## Pattern 3: Route Guard — Role-Based Access

```typescript
it('PENTEST: should block non-admin users from accessing admin routes', async () => {
  await allure.epic('Authentication');
  await allure.feature('Role-Based Access Control');
  await allure.story('Regular user cannot access admin panel');
  await allure.severity('blocker');
  await allure.tag('Pentest');
  await allure.tag('OWASP A01');
  await allure.tag('GOES Checklist R24');
  await allure.tag('GOES Checklist R34');
  await allure.description(
    '## Vulnerability prevented\n' +
    '**Privilege Escalation** — A regular user manually types\n' +
    'an admin URL to access restricted functionality.\n\n' +
    '## Defense implemented\n' +
    'Route meta fields define required roles. Navigation guard\n' +
    'checks user role against route requirements before allowing access.',
  );

  await allure.parameter('user_role', 'USER');
  await allure.parameter('required_role', 'ADMIN');
  await allure.parameter('route', '/admin/users');

  await allure.step('Prepare: set user as regular USER', async () => {
    const authStore = useAuthStore();
    authStore.user = { id: '1', role: 'USER' };
    authStore.token = 'valid-token';
  });

  await attach('Attacker state (input)', {
    userId: '1', role: 'USER', attemptedRoute: '/admin/users',
  });

  await allure.step('Execute: regular user tries to access admin route', async () => {
    await router.push('/admin/users');
  });

  await allure.step('Verify: access denied, redirected to forbidden or home', async () => {
    expect(router.currentRoute.value.path).not.toBe('/admin/users');
  });

  await attach('Defense result (output)', {
    accessDenied: true,
    reason: 'Insufficient role: USER cannot access ADMIN routes',
  });
});
```

## Pattern 4: PENTEST — Token Storage Security

```typescript
it('PENTEST: should NOT store auth tokens in localStorage or sessionStorage', async () => {
  await allure.epic('Security');
  await allure.feature('Secure Token Storage');
  await allure.story('Tokens must be in httpOnly cookies, not browser storage');
  await allure.severity('blocker');
  await allure.tag('Pentest');
  await allure.tag('OWASP A02');
  await allure.tag('GOES Checklist R42');
  await allure.description(
    '## Vulnerability prevented\n' +
    '**Token Theft via XSS** — If tokens are stored in localStorage,\n' +
    'any XSS vulnerability allows an attacker to steal them with\n' +
    '`document.cookie` or `localStorage.getItem()`.\n\n' +
    '## Defense implemented\n' +
    'Auth tokens are stored in httpOnly cookies (not accessible via JS)\n' +
    'or in memory (Pinia store) that is cleared on page refresh.',
  );

  await allure.step('Prepare: spy on localStorage and sessionStorage', async () => {
    vi.spyOn(Storage.prototype, 'setItem');
  });

  await allure.step('Execute: perform login flow', async () => {
    const authStore = useAuthStore();
    await authStore.login({ email: 'test@test.com', password: 'password' });
  });

  await allure.step('Verify: no tokens in localStorage', async () => {
    const localStorageCalls = vi.mocked(localStorage.setItem).mock.calls;
    const tokenKeys = localStorageCalls.filter(([key]) =>
      key.toLowerCase().includes('token') ||
      key.toLowerCase().includes('jwt') ||
      key.toLowerCase().includes('auth')
    );
    expect(tokenKeys).toHaveLength(0);
  });

  await allure.step('Verify: no tokens in sessionStorage', async () => {
    const sessionCalls = vi.mocked(sessionStorage.setItem).mock.calls;
    const tokenKeys = sessionCalls.filter(([key]) =>
      key.toLowerCase().includes('token') ||
      key.toLowerCase().includes('jwt') ||
      key.toLowerCase().includes('auth')
    );
    expect(tokenKeys).toHaveLength(0);
  });

  await attach('Defense result (output)', {
    localStorageTokens: 0,
    sessionStorageTokens: 0,
    storageMethod: 'httpOnly cookie or in-memory only',
  });
});
```

## Pattern 5: API Interceptor — 401 Handling

```typescript
it('should redirect to login and clear tokens on 401 response', async () => {
  await allure.epic('Authentication');
  await allure.feature('401 Error Handling');
  await allure.story('Clear auth state and redirect on unauthorized response');
  await allure.severity('critical');
  await allure.tag('Auth');
  await allure.tag('OWASP A07');
  await allure.tag('GOES Checklist VF4');
  await allure.description(
    '## Objective\n' +
    'Verify that when the API returns 401, the app clears all\n' +
    'auth state and redirects the user to login.\n\n' +
    '## Expected behavior\n' +
    '- API interceptor catches 401\n' +
    '- Auth store is cleared (token, user data)\n' +
    '- User is redirected to /login',
  );

  await allure.step('Prepare: mock API to return 401', async () => {
    vi.mocked(api.get).mockRejectedValue({
      response: { status: 401, data: { message: 'Token expired' } },
    });
  });

  const authStore = useAuthStore();

  await allure.step('Execute: make authenticated API call', async () => {
    try {
      await authStore.fetchProfile();
    } catch {
      // Expected to fail
    }
  });

  await allure.step('Verify: auth state cleared', async () => {
    expect(authStore.token).toBeNull();
    expect(authStore.user).toBeNull();
  });

  await allure.step('Verify: redirected to login', async () => {
    expect(router.currentRoute.value.path).toBe('/login');
  });

  await attach('Defense result (output)', {
    tokenCleared: true,
    userCleared: true,
    redirectedTo: '/login',
  });
});
```

## Pattern 6: Environment Variable Security

```typescript
it('PENTEST: should not expose secrets in VITE_ environment variables', async () => {
  await allure.epic('Security');
  await allure.feature('Environment Variable Security');
  await allure.story('No secrets or API keys in client-accessible env vars');
  await allure.severity('blocker');
  await allure.tag('Pentest');
  await allure.tag('OWASP A05');
  await allure.tag('GOES Checklist R3');
  await allure.tag('GOES Checklist VF6');
  await allure.tag('GOES Checklist VF10');
  await allure.description(
    '## Vulnerability prevented\n' +
    '**Secret Exposure** — Any VITE_ prefixed env variable is\n' +
    'embedded in the client bundle and visible to anyone.\n\n' +
    '## Defense implemented\n' +
    'Only public configuration (API URLs, feature flags) should\n' +
    'use VITE_ prefix. Secrets stay server-side only.',
  );

  await allure.step('Verify: no secrets in import.meta.env', async () => {
    const envKeys = Object.keys(import.meta.env);
    const suspiciousKeys = envKeys.filter((key) =>
      key.match(/SECRET|PASSWORD|PRIVATE|KEY|TOKEN|API_KEY/i) &&
      key.startsWith('VITE_')
    );
    expect(suspiciousKeys).toHaveLength(0);
  });

  await attach('Env vars audited (output)', {
    totalViteVars: Object.keys(import.meta.env).filter(k => k.startsWith('VITE_')).length,
    secretsFound: 0,
  });
});
```

## Pattern 7: Store Cleanup on Logout

```typescript
it('should clear all sensitive data from store on logout', async () => {
  await allure.epic('Security');
  await allure.feature('Store Cleanup on Logout');
  await allure.story('No sensitive data remains in Pinia store after logout');
  await allure.severity('critical');
  await allure.tag('Auth');
  await allure.tag('OWASP A02');
  await allure.tag('GOES Checklist VF7');
  await allure.description(
    '## Objective\n' +
    'Verify that after logout, no sensitive user data remains\n' +
    'in the Pinia store (tokens, personal info, permissions).\n\n' +
    '## Expected behavior\n' +
    '- All auth-related state is reset\n' +
    '- User object is null\n' +
    '- Token is null\n' +
    '- Permissions/roles are cleared',
  );

  const authStore = useAuthStore();

  await allure.step('Prepare: simulate logged-in state', async () => {
    authStore.token = 'valid-token';
    authStore.user = { id: '1', email: 'user@test.com', role: 'ADMIN' };
  });

  await allure.step('Execute: logout', async () => {
    await authStore.logout();
  });

  await allure.step('Verify: all sensitive data cleared', async () => {
    expect(authStore.token).toBeNull();
    expect(authStore.user).toBeNull();
    expect(authStore.isAuthenticated).toBe(false);
  });

  await attach('Store state after logout (output)', {
    token: authStore.token,
    user: authStore.user,
    isAuthenticated: authStore.isAuthenticated,
  });
});
```

## Pattern 8: Console.log in Production

```typescript
it('should not have console.log calls in production components', async () => {
  await allure.epic('Security');
  await allure.feature('Log Exposure Prevention');
  await allure.story('No console.log statements in production code');
  await allure.severity('critical');
  await allure.tag('Config');
  await allure.tag('OWASP A09');
  await allure.tag('GOES Checklist R10');
  await allure.description(
    '## Objective\n' +
    'Verify that production builds do not contain console.log\n' +
    'statements that could leak sensitive information.\n\n' +
    '## Defense\n' +
    'Use Vite plugin or ESLint rule to strip console.* in production.',
  );

  await allure.step('Verify: console.log spy not called during render', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const wrapper = mount(MyComponent);
    // Trigger component lifecycle
    await wrapper.vm.$nextTick();

    expect(consoleSpy).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  await attach('Result (output)', {
    consoleLogCalls: 0,
    status: 'No sensitive logs exposed',
  });
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
