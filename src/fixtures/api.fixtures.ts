/**
 * Playwright test fixtures.
 *
 * Provides pre-authenticated API clients to every test.
 * Tests declare which contexts they need in their parameters —
 * the fixture layer handles token acquisition and client wiring.
 *
 * Usage in a test file:
 *   import { test, expect } from '../fixtures/api.fixtures';
 *
 *   test('admin can access user list', async ({ adminSession, usersClient }) => {
 *     const { response } = await usersClient.getAllUsers(adminSession.accessToken);
 *     expect(response.status()).toBe(200);
 *   });
 */

import { test as base, expect } from '@playwright/test';
import { AuthSession } from '../lib/auth-session';
import { AuthClient } from '../client/auth.client';
import { UsersClient } from '../client/users.client';
import { ProductsClient } from '../client/products.client';
import { CartsClient } from '../client/carts.client';
import { AuthContext } from '../types/api.types';

// Declare the types of our custom fixtures
type ApiFixtures = {
  adminSession: AuthContext;
  userSession: AuthContext;
  secondUserSession: AuthContext;
  authClient: AuthClient;
  usersClient: UsersClient;
  productsClient: ProductsClient;
  cartsClient: CartsClient;
};

export const test = base.extend<ApiFixtures>({
  // ── Auth sessions (established once per test, cached across tests) ──────────

  adminSession: async ({ request }, use) => {
    const session = await AuthSession.forAdmin(request);
    await use(session);
  },

  userSession: async ({ request }, use) => {
    const session = await AuthSession.forUser(request);
    await use(session);
  },

  secondUserSession: async ({ request }, use) => {
    const session = await AuthSession.forSecondUser(request);
    await use(session);
  },

  // ── API clients ──────────────────────────────────────────────────────────────

  authClient: async ({ request }, use) => {
    await use(new AuthClient(request));
  },

  usersClient: async ({ request }, use) => {
    await use(new UsersClient(request));
  },

  productsClient: async ({ request }, use) => {
    await use(new ProductsClient(request));
  },

  cartsClient: async ({ request }, use) => {
    await use(new CartsClient(request));
  },
});

export { expect };
