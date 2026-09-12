/**
 * Authentication and Token Handling Tests
 *
 * Covers:
 * - Valid login returns tokens (AUTH-001)
 * - Invalid credentials rejected (AUTH-002, AUTH-003)
 * - /auth/me requires valid token (AUTH-004, AUTH-005, AUTH-006)
 * - Token refresh works (AUTH-007, AUTH-008)
 *
 * Security intent: Protected operations should require valid authentication.
 * Invalid and unauthorised requests should fail safely and consistently.
 *
 * NOTE: Some tests are expected to FAIL against DummyJSON because the sandbox
 * does not implement production-grade security. Failures are findings, not bugs.
 * Per the assessment brief: "do not change an expected outcome to make the suite pass."
 */

import { test, expect } from '../../src/fixtures/api.fixtures';
import { validateSchema } from '../../src/lib/schemas';
import { LoginResponseSchema, RefreshResponseSchema, AuthMeResponseSchema } from '../../src/lib/schemas';
import { logger } from '../../src/utils/logger';
import { redactObject } from '../../src/utils/redact';
import { severity, securityArea, classification, owasp, tag } from '../../src/utils/allure';

test.describe('Authentication and Identity', () => {

  test.describe('Login', () => {

    // AUTH-001 — PASS expected
    test('valid admin credentials return 200 with access and refresh tokens', async ({ authClient, adminSession }) => {
      securityArea('Authentication'); severity('critical'); classification('contract'); tag('AUTH-001');
      const { response, data } = await authClient.login({
        username: process.env.ADMIN_USERNAME!,
        password: process.env.ADMIN_PASSWORD!,
      });

      expect(response.status(), 'Login should return 200').toBe(200);

      const validation = validateSchema(LoginResponseSchema, data);
      expect(validation.success, `Login response schema invalid: ${!validation.success ? (validation as { error: string }).error : ''}`).toBe(true);

      expect(data.accessToken, 'accessToken must be a non-empty string').toBeTruthy();
      expect(data.refreshToken, 'refreshToken must be a non-empty string').toBeTruthy();

      const accessParts = data.accessToken.split('.');
      expect(accessParts.length, 'accessToken should be a JWT (3 parts)').toBe(3);

      logger.info('AUTH-001 passed', redactObject({ username: data.username, id: data.id }));
    });

    // AUTH-002 — PASS expected
    test('invalid password returns 400 with error message and no token', async ({ authClient }) => {
      securityArea('Authentication'); severity('critical'); classification('contract'); tag('AUTH-002'); owasp('API2:2023');
      const { response, data } = await authClient.loginWithInvalidCredentials(
        process.env.ADMIN_USERNAME!,
        'definitely-wrong-password-xyz123'
      );

      expect(response.status(), 'Invalid credentials should return 400').toBe(400);
      expect(data.message, 'Error response must include message field').toBeTruthy();
      expect((data as Record<string, unknown>).accessToken, 'Error response must not contain accessToken').toBeUndefined();
      expect((data as Record<string, unknown>).refreshToken, 'Error response must not contain refreshToken').toBeUndefined();
      expect((data as Record<string, unknown>).password, 'Error response must not echo password').toBeUndefined();

      logger.info('AUTH-002 passed — invalid password correctly rejected');
    });

    // AUTH-003 — PASS expected
    test('empty username and password returns 400', async ({ authClient }) => {
      const { response, data } = await authClient.loginWithInvalidCredentials('', '');

      expect(response.status(), 'Empty credentials should return 400').toBe(400);
      expect(data.message, 'Error response must have message').toBeTruthy();

      logger.info('AUTH-003 passed — empty credentials rejected');
    });

    // PASS expected
    test('login with non-existent username returns 400', async ({ authClient }) => {
      const { response, data } = await authClient.loginWithInvalidCredentials(
        'user_that_does_not_exist_xqz987',
        'somepassword'
      );

      expect(response.status(), 'Non-existent username should return 400').toBe(400);
      expect(data.message).toBeTruthy();
    });

    // EXP-002 — PASS expected (login endpoint correctly omits sensitive fields)
    test('login response does not expose sensitive fields', async ({ authClient }) => {
      const { response, data } = await authClient.login({
        username: process.env.ADMIN_USERNAME!,
        password: process.env.ADMIN_PASSWORD!,
      });

      expect(response.status()).toBe(200);

      const responseBody = data as unknown as Record<string, unknown>;

      expect(responseBody.password, 'EXP-002: Login response must not expose password').toBeUndefined();
      expect(responseBody.ssn, 'Login response must not expose SSN').toBeUndefined();
      expect(responseBody.bank, 'Login response must not expose bank details').toBeUndefined();
      expect(responseBody.cardNumber, 'Login response must not expose card number').toBeUndefined();

      logger.info('EXP-002 passed — login response does not expose sensitive fields');
    });
  });

  test.describe('GET /auth/me — Current User', () => {

    // AUTH-004 — PASS expected
    test('valid token returns current user profile', async ({ authClient, userSession }) => {
      const { response, data } = await authClient.getMe(userSession.accessToken);

      expect(response.status(), 'GET /auth/me with valid token should return 200').toBe(200);

      const validation = validateSchema(AuthMeResponseSchema, data);
      expect(
        validation.success,
        `GET /auth/me response schema invalid: ${!validation.success ? (validation as { error: string }).error : ''}`
      ).toBe(true);

      expect(data.username, '/auth/me must return the authenticated user').toBe(userSession.username);

      logger.info('AUTH-004 passed — /auth/me returns correct user for token');
    });

    // AUTH-005 — PASS expected (DummyJSON does enforce this)
    test('missing token returns 401', async ({ authClient }) => {
      const { response } = await authClient.getMe('');

      expect(response.status(), 'GET /auth/me without token should return 401').toBe(401);
      logger.info('AUTH-005 passed — /auth/me correctly rejects missing token');
    });

    // AUTH-006 — PASS expected
    test('malformed token returns 401', async ({ authClient }) => {
      const malformedToken = 'not.a.valid.jwt.token.at.all';
      const { response } = await authClient.getMe(malformedToken);

      expect(response.status(), 'GET /auth/me with malformed token should return 401').toBe(401);
      logger.info('AUTH-006 passed — malformed token rejected');
    });

    /**
     * AUTH-006b — EXPECTED TO FAIL on DummyJSON
     *
     * Production expectation: a structurally valid JWT with an invalid signature
     * should return 401 (Unauthorised). The server should detect the bad signature
     * and cleanly reject it.
     *
     * Observed DummyJSON behaviour: returns 500 (Internal Server Error).
     * This is a MEDIUM finding — the server crashes on signature validation
     * instead of handling it gracefully. A 500 leaks that an exception occurred
     * internally and violates the principle of "failing safely".
     *
     * Classification: finding — observed gap from production security expectation.
     */
    test('[FINDING] forged JWT with invalid signature should return 401 — DummyJSON returns 500', async ({ authClient }) => {
      securityArea('Token Handling'); severity('normal'); classification('finding'); owasp('API2:2023'); tag('AUTH-006b');
      const fakeHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const fakePayload = Buffer.from(JSON.stringify({ sub: '1', exp: 1000000 })).toString('base64url');
      const fakeToken = `${fakeHeader}.${fakePayload}.invalidsignature`;

      const { response } = await authClient.getMe(fakeToken);

      const actualStatus = response.status();

      logger.finding(
        'AUTH-006b',
        `GET /auth/me with a structurally valid JWT but invalid signature returned ${actualStatus}. ` +
        `Production expectation: 401. ` +
        `A 500 response suggests the token validation logic throws an unhandled exception rather than ` +
        `returning a clean rejection. This violates OWASP API Security — invalid inputs must fail safely.`,
        actualStatus === 500 ? 'MEDIUM' : 'LOW'
      );

      // Assert the production expectation — this will FAIL on DummyJSON (500 ≠ 401)
      // That failure IS the finding. We do not change this to make the test pass.
      expect(response.status(), 'AUTH-006b: Forged JWT must be rejected with 401, not crash the server').toBe(401);
    });
  });

  test.describe('Token Refresh', () => {

    // AUTH-007 — PASS expected
    test('valid refresh token returns new access and refresh tokens', async ({ authClient, userSession }) => {
      const { response, data } = await authClient.refresh(userSession.refreshToken);

      expect(response.status(), 'Token refresh with valid token should return 200').toBe(200);

      const validation = validateSchema(RefreshResponseSchema, data);
      expect(
        validation.success,
        `Refresh response schema invalid: ${!validation.success ? (validation as { error: string }).error : ''}`
      ).toBe(true);

      expect(data.accessToken, 'Refresh must return new accessToken').toBeTruthy();
      expect(data.refreshToken, 'Refresh must return new refreshToken').toBeTruthy();

      logger.info('AUTH-007 passed — token refresh works');
    });

    /**
     * AUTH-008 — EXPECTED TO FAIL on DummyJSON
     *
     * Production expectation: an invalid refresh token should return 401 (Unauthorised).
     * 401 is the semantically correct response — the credential is not recognised.
     *
     * Observed DummyJSON behaviour: returns 403 (Forbidden).
     * 403 is not incorrect per se — the request is rejected — but 401 is more
     * accurate because the identity cannot be established, not that access is denied
     * to a known identity. This is a minor contract deviation worth documenting.
     */
    test('[FINDING] invalid refresh token should return 401 — DummyJSON returns 403', async ({ authClient }) => {
      securityArea('Token Handling'); severity('trivial'); classification('finding'); owasp('API2:2023'); tag('AUTH-008');
      const { response } = await authClient.refresh('invalid-refresh-token-xyz');

      const actualStatus = response.status();

      logger.finding(
        'AUTH-008',
        `POST /auth/refresh with invalid token returned ${actualStatus}. ` +
        `Production expectation: 401 (Unauthorised). ` +
        `DummyJSON returns 403 (Forbidden). While both reject the request, ` +
        `401 is semantically correct when the credential itself is unrecognisable. ` +
        `403 implies the identity is known but access is denied — incorrect for a bad token.`,
        'LOW'
      );

      // Assert production expectation — will FAIL on DummyJSON (403 ≠ 401)
      expect(response.status(), 'AUTH-008: Invalid refresh token must return 401').toBe(401);
    });

    // PASS expected
    test('empty refresh token returns 401 or 400', async ({ authClient }) => {
      const { response } = await authClient.refresh('');

      expect([400, 401], 'Empty refresh token should be rejected').toContain(response.status());
    });
  });
});
