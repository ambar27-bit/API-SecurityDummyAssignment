/**
 * Base API client.
 *
 * Wraps Playwright's APIRequestContext to provide:
 * - Consistent error handling
 * - Automatic auth header injection
 * - Safe response parsing
 * - Request/response logging with redaction
 *
 * Test files NEVER import APIRequestContext directly — they always
 * go through a typed client. This separates low-level HTTP mechanics
 * from test intent and assertions.
 */

import { APIRequestContext, APIResponse } from '@playwright/test';
import { logger } from '../utils/logger';

export interface RequestOptions {
  token?: string;
  params?: Record<string, string | number | boolean>;
  body?: unknown;
}

export class BaseClient {
  constructor(
    protected readonly request: APIRequestContext,
    protected readonly baseUrl: string
  ) {}

  protected buildHeaders(token?: string): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  }

  protected buildUrl(path: string): string {
    return `${this.baseUrl}${path}`;
  }

  async get<T>(path: string, options: RequestOptions = {}): Promise<{ response: APIResponse; data: T }> {
    const url = this.buildUrl(path);
    const headers = this.buildHeaders(options.token);

    logger.request('GET', path, !!options.token);

    const response = await this.request.get(url, {
      headers,
      params: options.params as Record<string, string>,
    });

    logger.response('GET', path, response.status());
    const data = await this.parseResponse<T>(response);
    return { response, data };
  }

  async post<T>(path: string, options: RequestOptions = {}): Promise<{ response: APIResponse; data: T }> {
    const url = this.buildUrl(path);
    const headers = this.buildHeaders(options.token);

    logger.request('POST', path, !!options.token);

    const response = await this.request.post(url, {
      headers,
      data: options.body,
    });

    logger.response('POST', path, response.status());
    const data = await this.parseResponse<T>(response);
    return { response, data };
  }

  async put<T>(path: string, options: RequestOptions = {}): Promise<{ response: APIResponse; data: T }> {
    const url = this.buildUrl(path);
    const headers = this.buildHeaders(options.token);

    logger.request('PUT', path, !!options.token);

    const response = await this.request.put(url, {
      headers,
      data: options.body,
    });

    logger.response('PUT', path, response.status());
    const data = await this.parseResponse<T>(response);
    return { response, data };
  }

  async patch<T>(path: string, options: RequestOptions = {}): Promise<{ response: APIResponse; data: T }> {
    const url = this.buildUrl(path);
    const headers = this.buildHeaders(options.token);

    logger.request('PATCH', path, !!options.token);

    const response = await this.request.patch(url, {
      headers,
      data: options.body,
    });

    logger.response('PATCH', path, response.status());
    const data = await this.parseResponse<T>(response);
    return { response, data };
  }

  async delete<T>(path: string, options: RequestOptions = {}): Promise<{ response: APIResponse; data: T }> {
    const url = this.buildUrl(path);
    const headers = this.buildHeaders(options.token);

    logger.request('DELETE', path, !!options.token);

    const response = await this.request.delete(url, {
      headers,
    });

    logger.response('DELETE', path, response.status());
    const data = await this.parseResponse<T>(response);
    return { response, data };
  }

  private async parseResponse<T>(response: APIResponse): Promise<T> {
    const contentType = response.headers()['content-type'] || '';
    if (contentType.includes('application/json')) {
      try {
        return (await response.json()) as T;
      } catch {
        return {} as T;
      }
    }
    return {} as T;
  }
}
