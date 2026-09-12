/**
 * Users API client.
 * Covers both the public /users/* endpoints and
 * the authenticated /auth/users/* variants.
 */

import { APIRequestContext } from '@playwright/test';
import { BaseClient } from './base.client';
import { User, UsersListResponse, DeletedUser } from '../types/api.types';
import { config } from '../config/env';

export class UsersClient extends BaseClient {
  constructor(request: APIRequestContext) {
    super(request, config.baseUrl);
  }

  // ── Public (unauthenticated) endpoints ────────────────────────────────────

  /** GET /users — list all users (public, no token required) */
  async getAllUsers(token?: string) {
    return this.get<UsersListResponse>('/users', { token });
  }

  /** GET /users/{id} — get a single user (public, no token required) */
  async getUserById(id: number, token?: string) {
    return this.get<User>(`/users/${id}`, { token });
  }

  /** PUT /users/{id} — update a user (simulated, not persisted) */
  async updateUser(id: number, body: Partial<User>, token?: string) {
    return this.put<User>(`/users/${id}`, { body, token });
  }

  /** PATCH /users/{id} — partial update a user */
  async patchUser(id: number, body: Partial<User>, token?: string) {
    return this.patch<User>(`/users/${id}`, { body, token });
  }

  /** DELETE /users/{id} — delete a user (simulated, not persisted) */
  async deleteUser(id: number, token?: string) {
    return this.delete<DeletedUser>(`/users/${id}`, { token });
  }

  /** GET /users/search?q= — search users by query */
  async searchUsers(query: string, token?: string) {
    return this.get<UsersListResponse>('/users/search', {
      token,
      params: { q: query },
    });
  }

  /** GET /users/filter?key=&value= — filter users */
  async filterUsers(key: string, value: string, token?: string) {
    return this.get<UsersListResponse>('/users/filter', {
      token,
      params: { key, value },
    });
  }

  // ── Authenticated variants (/auth/ prefix) ────────────────────────────────

  /**
   * GET /auth/users — list users via the authenticated route.
   * Token is required; tests can omit it to verify 401 enforcement.
   */
  async getAllUsersAuthenticated(token?: string) {
    return this.get<UsersListResponse>('/auth/users', { token });
  }

  /** GET /auth/users/{id} — get a single user via the authenticated route */
  async getUserByIdAuthenticated(id: number, token?: string) {
    return this.get<User>(`/auth/users/${id}`, { token });
  }

  // ── User sub-resources ────────────────────────────────────────────────────

  /** GET /users/{id}/carts */
  async getUserCarts(userId: number, token?: string) {
    return this.get<{ carts: unknown[] }>(`/users/${userId}/carts`, { token });
  }

  /** GET /users/{id}/posts */
  async getUserPosts(userId: number, token?: string) {
    return this.get<{ posts: unknown[] }>(`/users/${userId}/posts`, { token });
  }

  /** GET /users/{id}/todos */
  async getUserTodos(userId: number, token?: string) {
    return this.get<{ todos: unknown[] }>(`/users/${userId}/todos`, { token });
  }
}
