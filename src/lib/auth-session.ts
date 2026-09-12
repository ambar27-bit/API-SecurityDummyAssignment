/**
 * AuthSession — programmatic authentication and token state management.
 *
 * In parallel execution mode, tokens are resolved from the global setup
 * state file written by global-setup.ts before workers start. This means:
 * - Only 3 login requests total regardless of worker count
 * - All workers share the same pre-authenticated tokens
 * - No race conditions on token acquisition
 *
 * In single-worker mode (or if the state file doesn't exist), falls back
 * to authenticating directly and caching in memory.
 *
 * Tokens are held in memory only — never written to logs or reports.
 */

import { APIRequestContext } from '@playwright/test';
import * as fs from 'fs';
import { AUTH_STATE_FILE } from './global-setup';
import { AuthClient } from '../client/auth.client';
import { AuthContext } from '../types/api.types';
import { config } from '../config/env';
import { logger } from '../utils/logger';

interface AuthStateFile {
  admin: AuthContext;
  user: AuthContext;
  secondUser: AuthContext;
}

function readAuthState(): AuthStateFile | null {
  try {
    if (fs.existsSync(AUTH_STATE_FILE)) {
      const raw = fs.readFileSync(AUTH_STATE_FILE, 'utf-8');
      return JSON.parse(raw) as AuthStateFile;
    }
  } catch {
    // Fall through to direct authentication
  }
  return null;
}

export class AuthSession {
  private static cache = new Map<string, AuthContext>();

  /**
   * Authenticate a user.
   * First checks the global setup state file (parallel-safe),
   * then falls back to in-memory cache, then authenticates directly.
   */
  static async authenticate(
    request: APIRequestContext,
    username: string,
    password: string
  ): Promise<AuthContext> {
    // Try global setup state file first (parallel-safe, single source of truth)
    const stateFile = readAuthState();
    if (stateFile) {
      if (username === config.adminUser.username) return stateFile.admin;
      if (username === config.regularUser.username) return stateFile.user;
      if (username === config.secondUser.username) return stateFile.secondUser;
    }

    // Fall back to per-worker in-memory cache
    if (AuthSession.cache.has(username)) {
      logger.debug(`Using cached auth context for user: ${username}`);
      return AuthSession.cache.get(username)!;
    }

    // Direct authentication (single-worker mode or missing state file)
    logger.info(`Authenticating user: ${username}`);
    const client = new AuthClient(request);
    const { response, data } = await client.login({ username, password });

    if (response.status() !== 200) {
      throw new Error(
        `Authentication failed for user "${username}": HTTP ${response.status()}. ` +
        `Check your .env credentials and that the DummyJSON service is reachable.`
      );
    }

    if (!data.accessToken || !data.refreshToken) {
      throw new Error(`Authentication response for "${username}" missing tokens.`);
    }

    const meClient = new AuthClient(request);
    const { data: profile } = await meClient.getMe(data.accessToken);

    const context: AuthContext = {
      userId: data.id,
      username: data.username,
      role: (profile.role as AuthContext['role']) ?? 'user',
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
    };

    AuthSession.cache.set(username, context);
    logger.info(`Authenticated: ${username} (id=${context.userId}, role=${context.role})`);
    return context;
  }

  static async forAdmin(request: APIRequestContext): Promise<AuthContext> {
    return AuthSession.authenticate(request, config.adminUser.username, config.adminUser.password);
  }

  static async forUser(request: APIRequestContext): Promise<AuthContext> {
    return AuthSession.authenticate(request, config.regularUser.username, config.regularUser.password);
  }

  static async forSecondUser(request: APIRequestContext): Promise<AuthContext> {
    return AuthSession.authenticate(request, config.secondUser.username, config.secondUser.password);
  }

  static clearCache(): void {
    AuthSession.cache.clear();
  }
}
