/**
 * Negative, Boundary and Error Scenario Tests
 *
 * Security intent:
 * - Invalid and unauthorised requests should fail safely, consistently,
 *   and without revealing avoidable information.
 *
 * Covers:
 * - Non-existent resource IDs (404 behaviour)
 * - Invalid ID types (boundary/type errors)
 * - Injection attempt payloads (safe error handling)
 * - Oversized/malformed request bodies
 * - HTTP method not allowed scenarios
 */

import { test, expect } from '../../src/fixtures/api.fixtures';
import { logger } from '../../src/utils/logger';

test.describe('Negative, Boundary and Error Scenarios', () => {

  test.describe('Non-Existent Resources', () => {

    // NEG-001
    test('GET /users/999999 returns 404 for non-existent user', async ({ usersClient }) => {
      const { response, data } = await usersClient.getUserById(999999);

      expect(response.status(), 'Non-existent user ID should return 404').toBe(404);
      expect((data as { message?: string }).message, 'Error response must contain message').toBeTruthy();

      // Must NOT reveal internal details in the error message
      const errorMessage = ((data as { message?: string }).message ?? '').toLowerCase();
      const leaksStack = /stack|at line|exception|traceback|sql|syntax/.test(errorMessage);
      expect(leaksStack, 'Error message must not reveal stack traces or internal details').toBe(false);

      logger.info('NEG-001 passed — 404 returned for non-existent user');
    });

    test('GET /products/999999 returns 404 for non-existent product', async ({ productsClient }) => {
      const { response } = await productsClient.getProductById(999999);

      expect(response.status()).toBe(404);
    });

    test('GET /carts/999999 returns 404 for non-existent cart', async ({ cartsClient }) => {
      const { response } = await cartsClient.getCartById(999999);

      expect(response.status()).toBe(404);
    });
  });

  test.describe('Invalid ID Types and Boundary Values', () => {

    // NEG-002
    test('GET /users/abc returns 400 for non-numeric ID', async ({ request }) => {
      const response = await request.get('https://dummyjson.com/users/abc');

      expect([400, 404], 'Non-numeric ID should return 400 or 404').toContain(response.status());

      logger.info(`NEG-002: GET /users/abc returned ${response.status()}`);
    });

    // NEG-004
    test('GET /users/0 — ID 0 is not a valid user', async ({ usersClient }) => {
      const { response } = await usersClient.getUserById(0);

      expect([400, 404], 'ID 0 is not a valid user — should return 4xx').toContain(response.status());

      logger.info(`NEG-004: GET /users/0 returned ${response.status()}`);
    });

    /**
     * NEG-005 — EXPECTED TO FAIL on DummyJSON
     *
     * Production expectation: -1 is not a valid user ID. The server should
     * reject it at the input validation layer with 400 (Bad Request).
     *
     * Observed DummyJSON behaviour: returns 404 (Not Found) — it treats -1
     * as a valid-format ID that simply doesn't exist rather than rejecting
     * the malformed input. Input validation should happen before DB lookup.
     */
    test('[FINDING] GET /users/-1 should return 400 for invalid negative ID — DummyJSON returns 404', async ({ request }) => {
      const response = await request.get('https://dummyjson.com/users/-1');

      const actualStatus = response.status();

      logger.finding(
        'NEG-005',
        `GET /users/-1 returned ${actualStatus}. Production expectation: 400. ` +
        `A negative integer is not a valid user ID. The API should validate input format ` +
        `and return 400 before attempting any lookup. Returning 404 leaks that the ID ` +
        `format was accepted as valid, which is incorrect.`,
        'LOW'
      );

      // Assert production expectation — FAILS on DummyJSON (404 ≠ 400)
      expect(actualStatus, 'NEG-005: Negative ID must be rejected as bad input with 400').toBe(400);
    });

    test('GET /users/1.5 — float ID is invalid', async ({ request }) => {
      const response = await request.get('https://dummyjson.com/users/1.5');

      expect([400, 404], 'Float ID should return 4xx').toContain(response.status());
    });
  });

  test.describe('Injection and Malformed Payloads', () => {

    // NEG-003
    test('SQL injection in login username does not cause 500 or stack trace', async ({ authClient }) => {
      const { response, data } = await authClient.loginWithInvalidCredentials(
        "' OR '1'='1",
        "' OR '1'='1"
      );

      // Must not return 500 (server error)
      expect(response.status(), 'SQL injection must not cause server error').not.toBe(500);
      expect([400, 401, 403], 'SQL injection must return a client error').toContain(response.status());

      // Must not leak internal info in error message
      const body = data as { message?: string };
      const errorText = (body.message ?? '').toLowerCase();
      const leaksInternal = /sql|syntax|exception|stack|error at|traceback/.test(errorText);
      expect(leaksInternal, 'Error response must not reveal SQL or internal details').toBe(false);

      logger.info(`NEG-003 passed — SQL injection in login returned ${response.status()} safely`);
    });

    test('XSS payload in login username does not reflect script tags', async ({ authClient }) => {
      const xssPayload = '<script>alert("xss")</script>';
      const { response, data } = await authClient.loginWithInvalidCredentials(xssPayload, 'test');

      expect(response.status()).not.toBe(500);

      // The response body must not echo back an unescaped script tag
      const responseText = JSON.stringify(data);
      expect(responseText.includes('<script>'), 'XSS payload must not be reflected unescaped').toBe(false);

      logger.info(`XSS payload test: login returned ${response.status()}`);
    });

    test('oversized username (1000 chars) does not cause server error', async ({ authClient }) => {
      const longUsername = 'a'.repeat(1000);
      const { response } = await authClient.loginWithInvalidCredentials(longUsername, 'test');

      expect(response.status(), 'Oversized input must not cause 500').not.toBe(500);
      expect([400, 401, 413], 'Oversized input should return 4xx').toContain(response.status());
    });

    test('null byte in username does not cause server error', async ({ authClient }) => {
      const { response } = await authClient.loginWithInvalidCredentials('user\x00name', 'pass');

      expect(response.status()).not.toBe(500);
    });
  });

  test.describe('Malformed Request Bodies', () => {

    test('POST /auth/login with non-JSON body returns error', async ({ request }) => {
      const response = await request.post('https://dummyjson.com/auth/login', {
        headers: { 'Content-Type': 'text/plain' },
        data: 'not json',
      });

      expect([400, 415, 422], 'Non-JSON body should return 4xx').toContain(response.status());
    });

    test('POST /auth/login with missing username field returns 400', async ({ request }) => {
      const response = await request.post('https://dummyjson.com/auth/login', {
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({ password: 'somepassword' }),
      });

      expect(response.status()).toBe(400);
    });

    test('POST /auth/login with missing password field returns 400', async ({ request }) => {
      const response = await request.post('https://dummyjson.com/auth/login', {
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({ username: 'emilys' }),
      });

      expect(response.status()).toBe(400);
    });
  });

  test.describe('HTTP Method Restrictions', () => {

    /**
     * EXPECTED TO FAIL on DummyJSON — documents observed behaviour
     *
     * Production expectation: PATCH on a POST-only endpoint should return
     * 405 (Method Not Allowed) with an Allow header listing valid methods.
     *
     * Observed DummyJSON behaviour: returns 401 (Unauthorised) — it treats
     * PATCH as an unauthenticated request to a protected route rather than
     * rejecting the method itself. This masks the real issue (wrong method)
     * behind an auth error, which is misleading for API consumers.
     */
    test('[FINDING] PATCH /auth/login should return 405 Method Not Allowed — DummyJSON returns 401', async ({ request }) => {
      const response = await request.patch('https://dummyjson.com/auth/login', {
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({ username: 'emilys', password: 'emilyspass' }),
      });

      const actualStatus = response.status();

      logger.finding(
        'NEG-006',
        `PATCH /auth/login returned ${actualStatus}. Production expectation: 405. ` +
        `Returning 401 instead of 405 obscures the real error (wrong HTTP method) ` +
        `behind an authentication error. An Allow response header should inform ` +
        `the caller which methods are valid for this endpoint.`,
        'LOW'
      );

      // Assert production expectation — FAILS on DummyJSON (401 ≠ 405)
      expect(actualStatus, 'Wrong HTTP method on login endpoint should return 405 Method Not Allowed').toBe(405);
    });
  });

  test.describe('Error Response Consistency', () => {

    test('all 4xx error responses include a message field', async ({ usersClient, authClient }) => {
      const cases = await Promise.all([
        usersClient.getUserById(999999),
        authClient.loginWithInvalidCredentials('baduser', 'badpass'),
      ]);

      for (const { response, data } of cases) {
        if (response.status() >= 400 && response.status() < 500) {
          expect(
            (data as { message?: string }).message,
            `HTTP ${response.status()} response must include message field`
          ).toBeTruthy();
        }
      }
    });

    test('error responses do not include Content-Type: text/html (no HTML error pages)', async ({ request }) => {
      const response = await request.get('https://dummyjson.com/users/999999');

      const contentType = response.headers()['content-type'] ?? '';
      expect(contentType.includes('text/html'), 'Error responses must not be HTML pages').toBe(false);
    });
  });
});
