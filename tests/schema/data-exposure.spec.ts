/**
 * Schema Validation and Data Exposure Tests
 *
 * Covers:
 * - Response bodies conform to documented schemas (contract tests)
 * - Sensitive fields that should not be exposed are flagged (security findings)
 *
 * Security intent:
 * - Sensitive information should not be unnecessarily exposed through API responses.
 *
 * DummyJSON DOES expose plaintext passwords, SSNs, bank card numbers
 * and other PII/PCI-sensitive data in user responses. These are documented
 * as critical security findings with production security expectations stated.
 */

import { test, expect } from '../../src/fixtures/api.fixtures';
import { validateSchema } from '../../src/lib/schemas';
import {
  LoginResponseSchema,
  UserSchema,
  UsersListSchema,
  ProductSchema,
  ProductsListSchema,
  CartSchema,
  CartsListSchema,
} from '../../src/lib/schemas';
import { logger } from '../../src/utils/logger';
import { redactObject } from '../../src/utils/redact';

test.describe('Schema Validation', () => {

  test.describe('Auth Endpoints', () => {

    // SCH-002
    test('POST /auth/login response matches LoginResponse schema', async ({ authClient }) => {
      const { response, data } = await authClient.login({
        username: process.env.ADMIN_USERNAME!,
        password: process.env.ADMIN_PASSWORD!,
      });

      expect(response.status()).toBe(200);

      const validation = validateSchema(LoginResponseSchema, data);
      expect(
        validation.success,
        `Schema validation failed: ${!validation.success ? (validation as { error: string }).error : ''}`
      ).toBe(true);

      logger.info('SCH-002 passed — login response matches schema');
    });
  });

  test.describe('Users Endpoints', () => {

    // SCH-001
    test('GET /users/{id} response matches User schema', async ({ usersClient }) => {
      const { response, data } = await usersClient.getUserById(1);

      expect(response.status()).toBe(200);

      const validation = validateSchema(UserSchema, data);
      expect(
        validation.success,
        `Schema validation failed: ${!validation.success ? (validation as { error: string }).error : ''}`
      ).toBe(true);

      logger.info('SCH-001 passed — user schema valid');
    });

    test('GET /users response matches UsersListResponse schema', async ({ usersClient }) => {
      const { response, data } = await usersClient.getAllUsers();

      expect(response.status()).toBe(200);

      const validation = validateSchema(UsersListSchema, data);
      expect(
        validation.success,
        `Schema validation failed: ${!validation.success ? (validation as { error: string }).error : ''}`
      ).toBe(true);

      // Pagination fields must be present and correct types
      expect(typeof data.total).toBe('number');
      expect(typeof data.skip).toBe('number');
      expect(typeof data.limit).toBe('number');
      expect(Array.isArray(data.users)).toBe(true);
    });

    test('user role field is always a known enum value', async ({ usersClient }) => {
      const { response, data } = await usersClient.getAllUsers();

      expect(response.status()).toBe(200);

      const validRoles = new Set(['admin', 'moderator', 'user']);
      const invalidRoles = data.users.filter((u) => !validRoles.has(u.role));

      expect(invalidRoles.length, `Found users with invalid role values: ${invalidRoles.map(u => u.role).join(', ')}`).toBe(0);
    });
  });

  test.describe('Products Endpoints', () => {

    // SCH-003
    test('GET /products response matches ProductsList schema', async ({ productsClient }) => {
      const { response, data } = await productsClient.getAllProducts();

      expect(response.status()).toBe(200);

      const validation = validateSchema(ProductsListSchema, data);
      expect(
        validation.success,
        `Schema validation failed: ${!validation.success ? (validation as { error: string }).error : ''}`
      ).toBe(true);

      logger.info('SCH-003 passed — products list schema valid');
    });

    test('GET /products/{id} response matches Product schema', async ({ productsClient }) => {
      const { response, data } = await productsClient.getProductById(1);

      expect(response.status()).toBe(200);

      const validation = validateSchema(ProductSchema, data);
      expect(
        validation.success,
        `Schema validation failed: ${!validation.success ? (validation as { error: string }).error : ''}`
      ).toBe(true);

      // Business rule: price must be non-negative
      expect(data.price, 'Product price must be >= 0').toBeGreaterThanOrEqual(0);
      // Rating must be in [0, 5]
      expect(data.rating, 'Rating must be between 0 and 5').toBeGreaterThanOrEqual(0);
      expect(data.rating, 'Rating must be between 0 and 5').toBeLessThanOrEqual(5);
    });
  });

  test.describe('Carts Endpoints', () => {

    // SCH-004
    test('GET /carts/{id} response matches Cart schema', async ({ cartsClient }) => {
      const { response, data } = await cartsClient.getCartById(1);

      expect(response.status()).toBe(200);

      const validation = validateSchema(CartSchema, data);
      expect(
        validation.success,
        `Schema validation failed: ${!validation.success ? (validation as { error: string }).error : ''}`
      ).toBe(true);

      logger.info('SCH-004 passed — cart schema valid');
    });

    test('GET /carts response matches CartsList schema', async ({ cartsClient }) => {
      const { response, data } = await cartsClient.getAllCarts();

      expect(response.status()).toBe(200);

      const validation = validateSchema(CartsListSchema, data);
      expect(
        validation.success,
        `Schema validation failed: ${!validation.success ? (validation as { error: string }).error : ''}`
      ).toBe(true);
    });
  });
});

test.describe('Data Exposure — Sensitive Field Analysis', () => {

  // EXP-001 — CRITICAL FINDING
  test('[FINDING] GET /users/{id} exposes plaintext password', async ({ usersClient }) => {
    const { response, data } = await usersClient.getUserById(1);

    expect(response.status()).toBe(200);

    const hasPassword = 'password' in data && typeof data.password === 'string' && data.password.length > 0;

    logger.finding(
      'EXP-001a',
      `GET /users/1 response contains a 'password' field with a non-empty value: ${hasPassword}. ` +
      `Production expectation: password must NEVER appear in any API response in any form. ` +
      `Plaintext passwords in API responses are a critical vulnerability — ` +
      `they violate OWASP API3:2023 (Broken Object Property Level Authorization) and basic credential hygiene.`,
      'CRITICAL'
    );

    // We assert that DummyJSON DOES include it (document observed behaviour)
    // The test itself is the evidence — a passing assertion with a security finding log
    expect(hasPassword, 'EXP-001: DummyJSON exposes password in user response (documented finding)').toBe(true);
  });

  test('[FINDING] GET /users/{id} exposes SSN', async ({ usersClient }) => {
    const { response, data } = await usersClient.getUserById(1);

    expect(response.status()).toBe(200);

    const hasSsn = 'ssn' in data && typeof data.ssn === 'string';

    logger.finding(
      'EXP-001b',
      `GET /users/1 response contains 'ssn' field: ${hasSsn}. ` +
      `SSN is highly sensitive PII that must never be returned in API responses without strict authorisation, ` +
      `masking and purpose limitation. Production expectation: omitted or fully masked.`,
      'CRITICAL'
    );

    expect(hasSsn).toBe(true);
  });

  test('[FINDING] GET /users/{id} exposes bank card number', async ({ usersClient }) => {
    const { response, data } = await usersClient.getUserById(1);

    expect(response.status()).toBe(200);

    const hasCardNumber = data.bank && 'cardNumber' in data.bank;

    logger.finding(
      'EXP-001c',
      `GET /users/1 response contains bank.cardNumber: ${hasCardNumber}. ` +
      `Full payment card numbers in API responses violate PCI-DSS requirements. ` +
      `Production expectation: omitted or masked (last 4 digits only).`,
      'CRITICAL'
    );

    expect(hasCardNumber).toBe(true);
  });

  test('[FINDING] GET /users/{id} exposes IBAN', async ({ usersClient }) => {
    const { response, data } = await usersClient.getUserById(1);

    expect(response.status()).toBe(200);
    const hasIban = data.bank && 'iban' in data.bank;

    logger.finding(
      'EXP-001d',
      `GET /users/1 contains bank.iban: ${hasIban}. ` +
      `IBAN is sensitive financial account data. Production: omit or mask.`,
      'HIGH'
    );

    expect(hasIban).toBe(true);
  });

  test('[FINDING] GET /users/{id} exposes EIN', async ({ usersClient }) => {
    const { response, data } = await usersClient.getUserById(1);
    const hasEin = 'ein' in data;

    logger.finding(
      'EXP-001e',
      `GET /users/1 contains 'ein' field: ${hasEin}. ` +
      `Employer Identification Number is a sensitive identifier. Production: omit.`,
      'HIGH'
    );

    expect(hasEin).toBe(true);
  });

  test('[FINDING] GET /users/{id} exposes crypto wallet address', async ({ usersClient }) => {
    const { response, data } = await usersClient.getUserById(1);
    const hasWallet = data.crypto && 'wallet' in data.crypto;

    logger.finding(
      'EXP-001f',
      `GET /users/1 contains crypto.wallet: ${hasWallet}. ` +
      `Crypto wallet addresses are financial identifiers. Production: omit or restrict to owner only.`,
      'MEDIUM'
    );

    expect(hasWallet).toBe(true);
  });

  test('login success response does not contain password', async ({ authClient }) => {
    const { response, data } = await authClient.login({
      username: process.env.ADMIN_USERNAME!,
      password: process.env.ADMIN_PASSWORD!,
    });

    expect(response.status()).toBe(200);

    // EXP-002 — Login should NOT expose the password (this should pass)
    expect((data as unknown as Record<string, unknown>).password, 'EXP-002: Login response must not include password').toBeUndefined();
    expect((data as unknown as Record<string, unknown>).ssn, 'Login response must not include SSN').toBeUndefined();

    logger.info('EXP-002 passed — login response does not expose password');
  });

  test('[FINDING] GET /users exposes all user passwords in list response', async ({ usersClient }) => {
    const { response, data } = await usersClient.getAllUsers();

    expect(response.status()).toBe(200);

    // Check how many users in the list have passwords exposed
    const usersWithPasswords = data.users.filter(
      (u) => 'password' in u && typeof (u as unknown as Record<string, unknown>).password === 'string'
    );

    logger.finding(
      'EXP-001g',
      `GET /users returns ${usersWithPasswords.length} of ${data.users.length} users with plaintext passwords in the list response. ` +
      `This represents a mass credential exposure endpoint accessible without authentication.`,
      'CRITICAL'
    );

    // Suppress actual password values from logs — just log count
    logger.info(`Password exposure count: ${usersWithPasswords.length}/${data.users.length} users`);
  });
});
