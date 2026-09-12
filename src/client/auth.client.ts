/**
 * Auth API client.
 * Handles login, token refresh and the /auth/me endpoint.
 */

import { APIRequestContext } from '@playwright/test';
import { BaseClient } from './base.client';
import { LoginResponse, RefreshResponse, AuthMeResponse } from '../types/api.types';
import { config } from '../config/env';

export interface LoginCredentials {
  username: string;
  password: string;
  expiresInMins?: number;
}

export class AuthClient extends BaseClient {
  constructor(request: APIRequestContext) {
    super(request, config.baseUrl);
  }

  /**
   * Authenticate with username/password.
   * Returns the full response so tests can assert on both
   * successful and failed login attempts.
   */
  async login(credentials: LoginCredentials) {
    return this.post<LoginResponse>('/auth/login', {
      body: {
        username: credentials.username,
        password: credentials.password,
        expiresInMins: credentials.expiresInMins ?? config.tokenExpiresInMins,
      },
    });
  }

  /**
   * Get the currently authenticated user's profile.
   * Requires a valid access token.
   */
  async getMe(token: string) {
    return this.get<AuthMeResponse>('/auth/me', { token });
  }

  /**
   * Refresh the access token using a refresh token.
   */
  async refresh(refreshToken: string) {
    return this.post<RefreshResponse>('/auth/refresh', {
      body: {
        refreshToken,
        expiresInMins: config.tokenExpiresInMins,
      },
    });
  }

  /**
   * Attempt login with deliberately invalid credentials.
   * Used in negative tests — expects a 400 response.
   */
  async loginWithInvalidCredentials(username: string, password: string) {
    return this.post<{ message: string }>('/auth/login', {
      body: { username, password },
    });
  }
}
