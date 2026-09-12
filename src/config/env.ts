/**
 * Environment configuration loader.
 *
 * Credential resolution order (first source that provides a value wins):
 *
 *   1. Secret manager environment injection
 *      In production or CI pipelines, a secret manager (AWS Secrets Manager,
 *      Azure Key Vault, HashiCorp Vault, GitHub Actions secrets etc.) injects
 *      values as environment variables before the process starts. No code change
 *      is needed — the process.env lookup below picks them up automatically.
 *      Example (AWS): `aws secretsmanager get-secret-value` piped into env vars
 *      Example (GitHub Actions): secrets.ADMIN_USERNAME → env: ADMIN_USERNAME
 *
 *   2. .env file (local development)
 *      dotenv is loaded in playwright.config.ts before any test code runs.
 *      Copy .env.example to .env and fill in values for local execution.
 *      The .env file is listed in .gitignore and must never be committed.
 *
 * Throws at startup if required variables are missing so tests fail
 * immediately with a clear message rather than silently using undefined
 * credentials mid-suite.
 *
 * SECRET MANAGER INTEGRATION NOTE:
 * If your organisation uses a centralised secret manager, the recommended
 * pattern is to resolve secrets at pipeline startup and inject them as
 * environment variables. This keeps the test framework secret-manager-agnostic
 * and avoids coupling test code to a specific cloud provider SDK.
 *
 * Example AWS SSM Parameter Store pre-step (shell):
 *   export ADMIN_USERNAME=$(aws ssm get-parameter --name /dummyjson/admin-username --with-decryption --query Parameter.Value --output text)
 *   export ADMIN_PASSWORD=$(aws ssm get-parameter --name /dummyjson/admin-password --with-decryption --query Parameter.Value --output text)
 *   npm test
 *
 * The config layer below then reads from process.env regardless of source.
 */

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value || value.trim() === '') {
    throw new Error(
      `Missing required environment variable: ${key}\n` +
      `Resolve via one of:\n` +
      `  - Local: copy .env.example to .env and fill in values\n` +
      `  - CI: set repository secrets (GitHub Actions: Settings → Secrets)\n` +
      `  - Production: inject from secret manager before running npm test`
    );
  }
  return value.trim();
}

function optionalEnv(key: string, defaultValue: string): string {
  const value = process.env[key];
  return value && value.trim() !== '' ? value.trim() : defaultValue;
}

export const config = {
  baseUrl: optionalEnv('BASE_URL', 'https://dummyjson.com'),

  adminUser: {
    username: requireEnv('ADMIN_USERNAME'),
    password: requireEnv('ADMIN_PASSWORD'),
  },

  regularUser: {
    username: requireEnv('USER_USERNAME'),
    password: requireEnv('USER_PASSWORD'),
  },

  secondUser: {
    username: requireEnv('USER2_USERNAME'),
    password: requireEnv('USER2_PASSWORD'),
  },

  tokenExpiresInMins: parseInt(optionalEnv('TOKEN_EXPIRES_IN_MINS', '60'), 10),
} as const;
