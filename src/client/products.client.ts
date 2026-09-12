/**
 * Products API client.
 */

import { APIRequestContext } from '@playwright/test';
import { BaseClient } from './base.client';
import { Product, ProductsListResponse } from '../types/api.types';
import { config } from '../config/env';

export class ProductsClient extends BaseClient {
  constructor(request: APIRequestContext) {
    super(request, config.baseUrl);
  }

  async getAllProducts(token?: string) {
    return this.get<ProductsListResponse>('/products', { token });
  }

  async getProductById(id: number, token?: string) {
    return this.get<Product>(`/products/${id}`, { token });
  }

  async addProduct(body: Partial<Product>, token?: string) {
    return this.post<Product>('/products/add', { body, token });
  }

  async updateProduct(id: number, body: Partial<Product>, token?: string) {
    return this.put<Product>(`/products/${id}`, { body, token });
  }

  async deleteProduct(id: number, token?: string) {
    return this.delete<Product & { isDeleted: boolean }>(`/products/${id}`, { token });
  }

  async getProductsByCategory(category: string, token?: string) {
    return this.get<ProductsListResponse>(`/products/category/${category}`, { token });
  }
}
