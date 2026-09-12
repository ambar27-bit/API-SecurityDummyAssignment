/**
 * AuthSession — programmatic authentication and token state management.
 *
 * Establishes and caches authenticated contexts for each user role.
 * Tests call `AuthSession.forAdmin()`, `AuthSession.forUser()` etc.
 * rather than managing tokens themselves.
 *
 * Tokens are held in memory only — never written to disk or logs.
 * The redactToken utility is used if tokens appear in diagnostic output.
 */

import { APIRequestContext } from '@playwright/test';
import { AuthClient } from '../client/auth.client';
import { AuthContext } from '../types/api.types';
import { config } from '../config/env';
import { logger } from '../utils/logger';

export class AuthSession {
  private static cache = new Map<string, AuthContext>();

  /**
   * Authenticate a user and cache the resulting context.
   * If already authenticated (within the same test worker process),
   * returns the cached context without a network call.
   */
  static async authenticate(
    request: APIRequestContext,
    username: string,
    password: string
  ): Promise<AuthContext> {
    const cacheKey = username;

    if (AuthSession.cache.has(cacheKey)) {
      logger.debug(`Using cached auth context for user: ${username}`);
      return AuthSession.cache.get(cacheKey)!;
    }

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
      throw new Error(`Authentication response for "${username}" missing tokens. Response shape unexpected.`);
    }

    // Fetch the user profile to get the role — login response doesn't include it
    const meClient = new AuthClient(request);
    const { data: profile } = await meClient.getMe(data.accessToken);

    const context: AuthContext = {
      userId: data.id,
      username: data.username,
      role: (profile.role as AuthContext['role']) ?? 'user',
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
    };

    AuthSession.cache.set(cacheKey, context);
    logger.info(`Authenticated: ${username} (id=${context.userId}, role=${context.role})`);
    return context;
  }

  /** Get or create an admin auth context */
  static async forAdmin(request: APIRequestContext): Promise<AuthContext> {
    return AuthSession.authenticate(request, config.adminUser.username, config.adminUser.password);
  }

  /** Get or create a regular user auth context */
  static async forUser(request: APIRequestContext): Promise<AuthContext> {
    return AuthSession.authenticate(request, config.regularUser.username, config.regularUser.password);
  }

  /** Get or create a second regular user auth context */
  static async forSecondUser(request: APIRequestContext): Promise<AuthContext> {
    return AuthSession.authenticate(request, config.secondUser.username, config.secondUser.password);
  }

  /**
   * Clear cached sessions.
   * Call this in afterAll if tests need fresh tokens.
   */
  static clearCache(): void {
    AuthSession.cache.clear();
  }
}
