/**
 * Resource Ownership and Cross-User Access Tests
 *
 * Security intent:
 * - A user should not access or modify another user's protected resources
 *   unless explicitly permitted.
 *
 * These tests use two distinct authenticated user sessions to probe
 * whether the API enforces ownership boundaries on user-scoped resources.
 *
 * All findings are classified against production security expectations.
 * DummyJSON does not enforce ownership — correctly identifying this is
 * a valid assessment outcome per the brief.
 */

import { test, expect } from '../../src/fixtures/api.fixtures';
import { logger } from '../../src/utils/logger';

test.describe('Resource Ownership and Cross-User Access', () => {

  test.describe('Cart Ownership', () => {

    // OWN-001 — user reads their own cart
    test('user can read their own cart via GET /carts/user/{ownId}', async ({
      cartsClient,
      userSession,
    }) => {
      const { response, data } = await cartsClient.getCartsByUser(userSession.userId, userSession.accessToken);

      expect(response.status(), 'User should be able to read their own cart').toBe(200);
      expect((data as { carts: unknown[] }).carts).toBeDefined();

      logger.info(`OWN-001 passed — user ${userSession.userId} can read their own cart`);
    });

    // OWN-002 — CRITICAL FINDING: cross-user cart access
    test('[FINDING] user can read another user\'s cart via GET /carts/user/{otherId}', async ({
      cartsClient,
      userSession,
      secondUserSession,
    }) => {
      // userSession tries to read secondUserSession's cart
      const otherId = secondUserSession.userId;
      const { response } = await cartsClient.getCartsByUser(otherId, userSession.accessToken);

      const actualStatus = response.status();

      logger.finding(
        'OWN-002',
        `GET /carts/user/${otherId} by user ${userSession.userId} (different user) returned ${actualStatus}. ` +
        `Production expectation: 403. ` +
        `No resource ownership check is enforced on the carts endpoint. ` +
        `Any authenticated user can read any other user's cart, exposing purchase history and product selections.`,
        'CRITICAL'
      );

      // DummyJSON returns 200 — document observed behaviour
      expect(actualStatus).toBe(200);
    });

    // Unauthenticated cross-user cart access
    test('[FINDING] unauthenticated GET /carts/user/{id} returns cart data', async ({
      cartsClient,
      userSession,
    }) => {
      const { response } = await cartsClient.getCartsByUser(userSession.userId); // no token

      const actualStatus = response.status();

      logger.finding(
        'OWN-002b',
        `GET /carts/user/${userSession.userId} without any authentication returns ${actualStatus}. ` +
        `Production expectation: 401. ` +
        `Cart data is accessible to unauthenticated requests.`,
        'HIGH'
      );

      expect(actualStatus).toBe(200);
    });
  });

  test.describe('Todos Ownership', () => {

    // OWN-003 — cross-user todos access
    test('[FINDING] user can read another user\'s todos', async ({
      usersClient,
      userSession,
      secondUserSession,
    }) => {
      const otherId = secondUserSession.userId;
      const { response } = await usersClient.getUserTodos(otherId, userSession.accessToken);

      const actualStatus = response.status();

      logger.finding(
        'OWN-003',
        `GET /users/${otherId}/todos by user ${userSession.userId} returned ${actualStatus}. ` +
        `Production expectation: 403. ` +
        `Todos are personal task data. Cross-user access should require admin role.`,
        'HIGH'
      );

      expect(actualStatus).toBe(200);
    });

    test('[FINDING] unauthenticated GET /users/{id}/todos returns data', async ({
      usersClient,
      secondUserSession,
    }) => {
      const { response } = await usersClient.getUserTodos(secondUserSession.userId); // no token

      expect(response.status()).toBe(200);
      logger.finding(
        'OWN-003b',
        `GET /users/${secondUserSession.userId}/todos without auth returns 200. Production expectation: 401.`,
        'MEDIUM'
      );
    });
  });

  test.describe('Posts Ownership', () => {

    test('[FINDING] user can read another user\'s posts without auth', async ({
      usersClient,
      secondUserSession,
    }) => {
      const { response } = await usersClient.getUserPosts(secondUserSession.userId); // no token

      expect(response.status()).toBe(200);
      logger.finding(
        'OWN-003c',
        `GET /users/${secondUserSession.userId}/posts without auth returns 200. ` +
        `Posts may be considered public content depending on app design, ` +
        `but unauthenticated access to user-scoped sub-resources still lacks access control.`,
        'LOW'
      );
    });
  });

  test.describe('User Record Mutation Ownership', () => {

    // OWN-004 — CRITICAL FINDING: cross-user write
    test('[FINDING] user can update another user\'s record via PUT /users/{otherId}', async ({
      usersClient,
      userSession,
      secondUserSession,
    }) => {
      const otherId = secondUserSession.userId;

      const { response, data } = await usersClient.updateUser(
        otherId,
        { firstName: 'HackedName' },
        userSession.accessToken
      );

      const actualStatus = response.status();

      logger.finding(
        'OWN-004',
        `PUT /users/${otherId} by user ${userSession.userId} (different user, role=${userSession.role}) returned ${actualStatus}. ` +
        `Production expectation: 403. ` +
        `Users must not be able to modify another user's record. This is a BOLA (Broken Object Level Authorization) vulnerability. ` +
        `Only the user themselves or an admin should be permitted to modify a user record.`,
        'CRITICAL'
      );

      expect(actualStatus).toBe(200);
      // DummyJSON simulates the update — note this doesn't persist
      expect((data as { firstName?: string }).firstName).toBe('HackedName');
    });

    // User updating their own record — should be allowed
    test('user can update their own record via PUT /users/{ownId}', async ({
      usersClient,
      userSession,
    }) => {
      const { response } = await usersClient.updateUser(
        userSession.userId,
        { firstName: 'UpdatedSelf' },
        userSession.accessToken
      );

      // DummyJSON allows this — in production this would also be permitted (own record)
      expect(response.status(), 'User should be able to update their own record').toBe(200);

      logger.info(`OWN-004-self: User ${userSession.userId} updating their own record returned ${response.status()}`);
    });

    test('[FINDING] unauthenticated PUT /users/{id} succeeds', async ({ usersClient, secondUserSession }) => {
      const { response } = await usersClient.updateUser(secondUserSession.userId, { lastName: 'NoAuthUpdate' });

      const actualStatus = response.status();

      logger.finding(
        'OWN-004b',
        `PUT /users/${secondUserSession.userId} without any authentication returns ${actualStatus}. ` +
        `Production expectation: 401.`,
        'CRITICAL'
      );

      expect(actualStatus).toBe(200);
    });
  });

  test.describe('Cart Direct Access', () => {

    test('[FINDING] GET /carts/{id} has no ownership enforcement', async ({
      cartsClient,
      userSession,
    }) => {
      // Cart ID 1 likely belongs to a different user (userId 142 based on docs)
      const { response, data } = await cartsClient.getCartById(1, userSession.accessToken);

      expect(response.status()).toBe(200);

      const cartUserId = (data as { userId?: number }).userId;
      if (cartUserId && cartUserId !== userSession.userId) {
        logger.finding(
          'OWN-005',
          `GET /carts/1 returned cart belonging to userId=${cartUserId}, ` +
          `accessed by userId=${userSession.userId}. ` +
          `No ownership or authorization check was performed. ` +
          `Any user can read any cart by guessing the cart ID.`,
          'HIGH'
        );
      }
    });
  });
});
