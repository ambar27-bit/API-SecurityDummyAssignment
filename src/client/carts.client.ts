/**
 * Carts API client.
 */

import { APIRequestContext } from '@playwright/test';
import { BaseClient } from './base.client';
import { Cart, CartsListResponse } from '../types/api.types';
import { config } from '../config/env';

export class CartsClient extends BaseClient {
  constructor(request: APIRequestContext) {
    super(request, config.baseUrl);
  }

  async getAllCarts(token?: string) {
    return this.get<CartsListResponse>('/carts', { token });
  }

  async getCartById(id: number, token?: string) {
    return this.get<Cart>(`/carts/${id}`, { token });
  }

  async getCartsByUser(userId: number, token?: string) {
    return this.get<CartsListResponse>(`/carts/user/${userId}`, { token });
  }

  async addCart(body: { userId: number; products: Array<{ id: number; quantity: number }> }, token?: string) {
    return this.post<Cart>('/carts/add', { body, token });
  }

  async updateCart(
    id: number,
    body: { merge?: boolean; products: Array<{ id: number; quantity: number }> },
    token?: string
  ) {
    return this.put<Cart>(`/carts/${id}`, { body, token });
  }

  async deleteCart(id: number, token?: string) {
    return this.delete<Cart & { isDeleted: boolean }>(`/carts/${id}`, { token });
  }
}
