/**
 * Data-Driven Security Matrix Test Runner
 *
 * Reads scenarios from data/security-matrix.json and executes each one.
 * This is the heart of the data-driven approach — adding a new scenario
 * requires only a JSON entry, not new test code.
 *
 * Each scenario carries:
 * - expected HTTP status
 * - production security expectation (where it differs)
 * - security classification (contract | hypothesis | finding)
 *
 * The runner asserts against the OBSERVED expected status (what DummyJSON
 * actually does) and logs the security classification as a finding when
 * the observed behaviour differs from a production expectation.
 */

import { test, expect } from '../../src/fixtures/api.fixtures';
import { AuthSession } from '../../src/lib/auth-session';
import { logger } from '../../src/utils/logger';
import * as path from 'path';
import * as fs from 'fs';

// Load matrix from data directory
const matrixPath = path.resolve(__dirname, '../../data/security-matrix.json');
const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf-8'));

type Scenario = {
  id: string;
  area: string;
  description: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  authContext: 'none' | 'admin' | 'user' | 'malformed_token' | 'invalid_refresh';
  expectedStatus: number;
  productionExpectedStatus?: number;
  securityClassification: 'contract' | 'hypothesis' | 'finding';
  securityHypothesis?: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  expectedFields?: string[];
  forbiddenFields?: string[];
  sensitiveFieldsPresent?: string[];
  credentialsKey?: string;
};

const scenarios: Scenario[] = matrix.scenarios;

/**
 * Resolve the endpoint URL, replacing {ownId}/{otherId} placeholders
 * with concrete user IDs from the auth context.
 */
function resolveEndpoint(
  endpoint: string,
  authContext: { userId?: number },
  otherUserId = 2
): string {
  return endpoint
    .replace('{ownId}', String(authContext.userId ?? 1))
    .replace('{otherId}', String(otherUserId));
}

/**
 * Build the request body for scenarios that require credentials.
 * Returns null to signal "needs fresh login for refresh token".
 */
async function buildBodyAsync(
  scenario: Scenario,
  request: import('@playwright/test').APIRequestContext
): Promise<Record<string, unknown> | undefined> {
  if (scenario.method !== 'POST' && scenario.method !== 'PUT') return undefined;

  if (scenario.credentialsKey === 'admin') {
    return {
      username: process.env.ADMIN_USERNAME,
      password: process.env.ADMIN_PASSWORD,
      expiresInMins: 30,
    };
  }
  if (scenario.credentialsKey === 'user') {
    return {
      username: process.env.USER_USERNAME,
      password: process.env.USER_PASSWORD,
      expiresInMins: 30,
    };
  }
  if (scenario.credentialsKey === 'invalid') {
    return { username: process.env.ADMIN_USERNAME, password: 'wrong-password-xyz' };
  }
  if (scenario.credentialsKey === 'empty') {
    return { username: '', password: '' };
  }
  if (scenario.credentialsKey === 'sqli') {
    return { username: "' OR '1'='1", password: "' OR '1'='1" };
  }
  if (scenario.credentialsKey === 'invalid_refresh') {
    return { refreshToken: 'invalid-refresh-token' };
  }
  if (scenario.credentialsKey === 'refresh_valid') {
    // Do a fresh login to get a fresh refresh token — avoids token reuse issues
    const loginRes = await request.post('https://dummyjson.com/auth/login', {
      headers: { 'Content-Type': 'application/json' },
      data: JSON.stringify({
        username: process.env.USER_USERNAME,
        password: process.env.USER_PASSWORD,
        expiresInMins: 30,
      }),
    });
    const loginData = await loginRes.json() as { refreshToken?: string };
    return { refreshToken: loginData.refreshToken, expiresInMins: 30 };
  }
  return undefined;
}

test.describe('Data-Driven Security Matrix', () => {

  for (const scenario of scenarios) {
    const label = `[${scenario.id}] [${scenario.securityClassification.toUpperCase()}] ${scenario.description}`;

    test(label, async ({ request, adminSession, userSession, secondUserSession }) => {
      // Resolve auth context
      let token: string | undefined;
      let resolvedEndpoint = scenario.endpoint;

      if (scenario.authContext === 'admin') {
        token = adminSession.accessToken;
        resolvedEndpoint = resolveEndpoint(scenario.endpoint, adminSession, userSession.userId);
      } else if (scenario.authContext === 'user') {
        token = userSession.accessToken;
        resolvedEndpoint = resolveEndpoint(scenario.endpoint, userSession, secondUserSession.userId);
      } else if (scenario.authContext === 'malformed_token') {
        token = 'not.a.valid.jwt';
        resolvedEndpoint = resolveEndpoint(scenario.endpoint, {});
      } else if (scenario.authContext === 'invalid_refresh') {
        token = undefined;
      }

      const url = `https://dummyjson.com${resolvedEndpoint}`;
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const body = await buildBodyAsync(scenario, request);

      // Execute the request
      let response;
      switch (scenario.method) {
        case 'GET':
          response = await request.get(url, { headers });
          break;
        case 'POST':
          response = await request.post(url, { headers, data: body });
          break;
        case 'PUT':
          response = await request.put(url, { headers, data: body });
          break;
        case 'PATCH':
          response = await request.patch(url, { headers, data: body });
          break;
        case 'DELETE':
          response = await request.delete(url, { headers });
          break;
      }

      const actualStatus = response.status();
      let responseData: Record<string, unknown> = {};
      try {
        responseData = await response.json();
      } catch {
        // Non-JSON response — ok
      }

      // Log security classifications
      if (scenario.securityClassification === 'finding' || scenario.securityClassification === 'hypothesis') {
        const gap = scenario.productionExpectedStatus
          ? `Observed: ${actualStatus}, Production expectation: ${scenario.productionExpectedStatus}`
          : '';

        if (scenario.securityHypothesis) {
          logger.finding(
            scenario.id,
            `${scenario.securityHypothesis} ${gap}`,
            scenario.priority === 'critical' ? 'CRITICAL'
              : scenario.priority === 'high' ? 'HIGH'
              : 'MEDIUM'
          );
        }
      }

      // Assert observed status
      expect(
        actualStatus,
        `${scenario.id}: Expected HTTP ${scenario.expectedStatus}, got ${actualStatus}`
      ).toBe(scenario.expectedStatus);

      // Assert expected fields are present
      if (scenario.expectedFields) {
        for (const field of scenario.expectedFields) {
          expect(
            responseData[field],
            `${scenario.id}: Expected field '${field}' in response`
          ).toBeDefined();
        }
      }

      // Assert forbidden fields are absent
      if (scenario.forbiddenFields) {
        for (const field of scenario.forbiddenFields) {
          expect(
            responseData[field],
            `${scenario.id}: Field '${field}' must NOT be in response`
          ).toBeUndefined();
        }
      }

      // Assert sensitive fields are present (document exposure finding)
      if (scenario.sensitiveFieldsPresent) {
        for (const fieldPath of scenario.sensitiveFieldsPresent) {
          const parts = fieldPath.split('.');
          let value: unknown = responseData;
          for (const part of parts) {
            value = (value as Record<string, unknown>)?.[part];
          }
          logger.finding(
            `${scenario.id}-${fieldPath}`,
            `Response field '${fieldPath}' is present in response body. This is a sensitive field that should be omitted or masked in production.`,
            'HIGH'
          );
          expect(value, `${scenario.id}: Sensitive field '${fieldPath}' documented as present`).toBeDefined();
        }
      }

      logger.info(`${scenario.id} ✓ — ${scenario.method} ${resolvedEndpoint} → ${actualStatus}`);
    });
  }
});
