import { defineConfig } from '@playwright/test';
import * as dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

export default defineConfig({
  testDir: './tests',
  globalSetup: './src/lib/global-setup.ts',
  globalTeardown: './src/lib/global-teardown.ts',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 2, // 2 concurrent workers — auth handled via global setup, no duplicate logins
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },

  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
    ['json', { outputFile: 'test-results/results.json' }],
    ['allure-playwright', {
      outputFolder: 'allure-results',
      detail: true,
      suiteTitle: true,
    }],
  ],

  use: {
    baseURL: process.env.BASE_URL || 'https://dummyjson.com',
    extraHTTPHeaders: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    // Never log request/response bodies automatically - we handle redaction manually
    trace: 'off',
  },

  projects: [
    {
      name: 'api-security',
      testMatch: '**/*.spec.ts',
    },
  ],

  outputDir: 'test-results',
});
