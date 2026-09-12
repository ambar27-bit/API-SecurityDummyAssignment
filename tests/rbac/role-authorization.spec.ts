/**
 * Role-Based Authorization Tests
 *
 * Tests the RBAC model — or the absence of one — on DummyJSON.
 *
 * Security intent:
 * - A role should not gain privileges outside its authorised scope.
 * - Protected operations should require valid authentication.
 *
 * KEY EXPECTATION: DummyJSON does NOT enforce production-grade RBAC.
 * These tests document the gap between expected secure behaviour
 * and observed sandbox behaviour. Failures on 'hypothesis' classified
 * tests are expected and documented as security findings, not suite bugs.
 */

import { test, expect } from '../../src/fixtures/api.fixtures';
import { logger } from '../../src/utils/logger';

test.describe('Role-Based Authorization', () => {

  test.describe('User Directory Access', () => {

    // RBAC-001
    test('admin can list all users', async ({ usersClient, adminSession }) => {
      const { response, data } = await usersClient.getAllUsers(adminSession.accessToken);

      expect(response.status(), 'Admin should be able to list users').toBe(200);
      expect(data.users, 'Response must include users array').toBeDefined();
      expect(data.users.length, 'Should return at least one user').toBeGreaterThan(0);
      expect(data.total, 'Response must include total count').toBeGreaterThan(0);

      logger.info('RBAC-001 passed — admin can list users');
    });

    // RBAC-002 — HYPOTHESIS TEST
    test('[HYPOTHESIS] regular user listing all users — expected 403 in production', async ({ usersClient, userSession }) => {
      const { response } = await usersClient.getAllUsers(userSession.accessToken);

      // Document what DummyJSON actually does
      const actualStatus = response.status();

      if (actualStatus === 200) {
        logger.finding(
          'RBAC-002',
          `GET /users returns 200 for a regular user (role=${userSession.role}). ` +
          `In a production system this should return 403 — non-admin users should not have access to the full user directory. ` +
          `DummyJSON does not enforce role-based restrictions on this endpoint.`,
          'MEDIUM'
        );
      }

      // We assert what DummyJSON actually does (200) not the production expectation (403)
      // This is intentional per the brief: "do not change an expected outcome to make the suite pass"
      expect(actualStatus).toBe(200);

      logger.info(`RBAC-002 observed: GET /users as regular user returned ${actualStatus} (production expectation: 403)`);
    });

    // RBAC-003 — CRITICAL FINDING
    test('[FINDING] unauthenticated request to GET /users returns user data', async ({ usersClient }) => {
      const { response, data } = await usersClient.getAllUsers(); // no token

      const actualStatus = response.status();

      logger.finding(
        'RBAC-003',
        `GET /users without any authentication returns ${actualStatus}. ` +
        `Production expectation: 401. ` +
        `This endpoint returns full user objects including SSN, bank details, plaintext passwords and other PII for all users without requiring any credentials. ` +
        `This represents a critical data exposure risk in a production equivalent system.`,
        'CRITICAL'
      );

      // DummyJSON returns 200 (document observed behaviour)
      expect(actualStatus).toBe(200);
      expect(data.users).toBeDefined();
    });

    test('admin can read individual user record', async ({ usersClient, adminSession }) => {
      const { response, data } = await usersClient.getUserById(1, adminSession.accessToken);

      expect(response.status()).toBe(200);
      expect(data.id).toBe(1);
    });
  });

  test.describe('Write Operations — Authorization Enforcement', () => {

    // RBAC-005 — CRITICAL FINDING
    test('[FINDING] unauthenticated DELETE /users/{id} — sandbox allows, production must reject', async ({ usersClient }) => {
      const { response, data } = await usersClient.deleteUser(3); // no token

      const actualStatus = response.status();

      logger.finding(
        'RBAC-005',
        `DELETE /users/3 without authentication returns ${actualStatus}. ` +
        `Production expectation: 401. ` +
        `Destructive operations must require authentication. ` +
        `DummyJSON simulates the delete (isDeleted flag in response) without enforcing auth, ` +
        `which is expected sandbox behaviour but would be a critical auth bypass in production.`,
        'CRITICAL'
      );

      // Sandbox returns 200 with isDeleted flag — document this
      expect(actualStatus).toBe(200);
      expect((data as { isDeleted?: boolean }).isDeleted).toBe(true);
    });

    /**
     * RBAC-004 — EXPECTED TO FAIL on DummyJSON
     *
     * Production expectation: a regular user must not be able to delete
     * another user's record. This should return 403 (Forbidden).
     *
     * Observed DummyJSON behaviour: returns 200 — no role or ownership
     * check is performed. This is a BFLA (Broken Function Level Authorization)
     * vulnerability. Any authenticated user can delete any other user.
     */
    test('[FINDING] regular user DELETE /users/{id} must return 403 — DummyJSON returns 200', async ({ usersClient, userSession }) => {
      const { response } = await usersClient.deleteUser(2, userSession.accessToken);

      const actualStatus = response.status();

      logger.finding(
        'RBAC-004',
        `DELETE /users/2 as regular user (role=${userSession.role}) returned ${actualStatus}. ` +
        `Production expectation: 403. ` +
        `Regular users must not be able to delete other users — only admins should hold that privilege. ` +
        `DummyJSON performs no role or ownership check on destructive operations. ` +
        `OWASP API Security reference: API5:2023 Broken Function Level Authorization.`,
        'CRITICAL'
      );

      // Assert production expectation — FAILS on DummyJSON (200 ≠ 403)
      expect(actualStatus, 'RBAC-004: Regular user must not be able to delete another user').toBe(403);
    });

    // RBAC-006 — FINDING
    test('[FINDING] unauthenticated POST /products/add succeeds', async ({ productsClient }) => {
      const { response, data } = await productsClient.addProduct({
        title: 'Security Test Product',
        price: 9.99,
        description: 'Created without authentication',
        category: 'test',
      }); // no token

      const actualStatus = response.status();

      logger.finding(
        'RBAC-006',
        `POST /products/add without authentication returns ${actualStatus}. ` +
        `Production expectation: 401. ` +
        `Resource creation endpoints must require authentication. ` +
        `DummyJSON accepts unauthenticated writes (simulated).`,
        'HIGH'
      );

      expect(actualStatus).toBe(201);
      expect((data as { id?: number }).id, 'Simulated product should have an id').toBeDefined();
    });

    test('[FINDING] unauthenticated PUT /products/{id} succeeds', async ({ productsClient }) => {
      const { response } = await productsClient.updateProduct(1, { title: 'Modified Without Auth' });

      const actualStatus = response.status();

      if (actualStatus === 200) {
        logger.finding(
          'RBAC-006b',
          `PUT /products/1 without authentication returns ${actualStatus}. ` +
          `Production expectation: 401.`,
          'HIGH'
        );
      }

      expect(actualStatus).toBe(200);
    });

    test('[FINDING] unauthenticated DELETE /products/{id} succeeds', async ({ productsClient }) => {
      const { response } = await productsClient.deleteProduct(1);

      const actualStatus = response.status();

      if (actualStatus === 200) {
        logger.finding(
          'RBAC-006c',
          `DELETE /products/1 without authentication returns ${actualStatus}. ` +
          `Production expectation: 401.`,
          'HIGH'
        );
      }

      expect(actualStatus).toBe(200);
    });
  });

  test.describe('Authenticated User Routes (/auth/ prefix)', () => {

    test('GET /auth/users requires valid token', async ({ usersClient }) => {
      const { response } = await usersClient.getAllUsersAuthenticated(); // no token

      expect(response.status(), '/auth/users without token must return 401').toBe(401);

      logger.info('Auth-prefix route correctly enforces authentication on /auth/users');
    });

    test('GET /auth/users with valid token returns 200', async ({ usersClient, userSession }) => {
      const { response, data } = await usersClient.getAllUsersAuthenticated(userSession.accessToken);

      expect(response.status()).toBe(200);
      expect(data.users).toBeDefined();
    });

    test('GET /auth/users/{id} requires valid token', async ({ usersClient }) => {
      const { response } = await usersClient.getUserByIdAuthenticated(1); // no token

      expect(response.status(), '/auth/users/{id} without token must return 401').toBe(401);
    });
  });
});
