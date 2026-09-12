/**
 * Playwright global setup — runs ONCE before all workers start.
 *
 * Authenticates all required user contexts and writes tokens to a
 * temporary file that all workers can read. This means:
 * - Only 3 login requests total regardless of worker count
 * - All workers share the same tokens — no duplicate auth calls
 * - Token state is consistent across parallel test runs
 *
 * The temp file is written to the OS temp directory and never
 * committed — tokens exist only for the duration of the test run.
 */

import { request } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as dotenv from 'dotenv';

dotenv.config();

export const AUTH_STATE_FILE = path.join(os.tmpdir(), 'api-test-auth-state.json');

interface UserAuth {
  userId: number;
  username: string;
  role: string;
  accessToken: string;
  refreshToken: string;
}

interface AuthState {
  admin: UserAuth;
  user: UserAuth;
  secondUser: UserAuth;
}

async function authenticateUser(
  requestContext: Awaited<ReturnType<typeof request.newContext>>,
  username: string,
  password: string
): Promise<UserAuth> {
  const baseUrl = process.env.BASE_URL || 'https://dummyjson.com';

  // Login
  const loginRes = await requestContext.post(`${baseUrl}/auth/login`, {
    headers: { 'Content-Type': 'application/json' },
    data: JSON.stringify({ username, password, expiresInMins: 60 }),
  });

  if (loginRes.status() !== 200) {
    throw new Error(
      `Global setup: authentication failed for "${username}": HTTP ${loginRes.status()}. ` +
      `Check your .env credentials.`
    );
  }

  const loginData = await loginRes.json();

  // Get profile to resolve role
  const meRes = await requestContext.get(`${baseUrl}/auth/me`, {
    headers: { Authorization: `Bearer ${loginData.accessToken}` },
  });

  const meData = await meRes.json();

  return {
    userId: loginData.id,
    username: loginData.username,
    role: meData.role ?? 'user',
    accessToken: loginData.accessToken,
    refreshToken: loginData.refreshToken,
  };
}

export default async function globalSetup(): Promise<void> {
  console.log('\n[Global Setup] Authenticating test users...');

  const requestContext = await request.newContext();

  try {
    const [admin, user, secondUser] = await Promise.all([
      authenticateUser(requestContext, process.env.ADMIN_USERNAME!, process.env.ADMIN_PASSWORD!),
      authenticateUser(requestContext, process.env.USER_USERNAME!, process.env.USER_PASSWORD!),
      authenticateUser(requestContext, process.env.USER2_USERNAME!, process.env.USER2_PASSWORD!),
    ]);

    const authState: AuthState = { admin, user, secondUser };

    // Write to temp file — workers will read this
    fs.writeFileSync(AUTH_STATE_FILE, JSON.stringify(authState), 'utf-8');

    console.log(`[Global Setup] Authenticated: ${admin.username} (${admin.role}), ${user.username} (${user.role}), ${secondUser.username} (${secondUser.role})`);
    console.log(`[Global Setup] Auth state written to: ${AUTH_STATE_FILE}`);
  } finally {
    await requestContext.dispose();
  }
}
