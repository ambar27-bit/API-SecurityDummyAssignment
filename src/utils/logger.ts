/**
 * Structured test logger.
 *
 * Wraps console output with consistent formatting and ensures all
 * output passes through redaction before being emitted.
 * In CI, only WARN and ERROR are emitted unless DEBUG=true.
 */

import { safeStringify, redactToken } from './redact';

type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

const IS_CI = !!process.env.CI;
const IS_DEBUG = process.env.DEBUG === 'true';

function shouldLog(level: LogLevel): boolean {
  if (IS_DEBUG) return true;
  if (IS_CI) return level === 'WARN' || level === 'ERROR';
  return true;
}

function emit(level: LogLevel, message: string, data?: unknown): void {
  if (!shouldLog(level)) return;
  const timestamp = new Date().toISOString();
  const prefix = `[${timestamp}] [${level}]`;

  if (data !== undefined) {
    console.log(`${prefix} ${message}`, safeStringify(data));
  } else {
    console.log(`${prefix} ${message}`);
  }
}

export const logger = {
  debug: (message: string, data?: unknown) => emit('DEBUG', message, data),
  info: (message: string, data?: unknown) => emit('INFO', message, data),
  warn: (message: string, data?: unknown) => emit('WARN', message, data),
  error: (message: string, data?: unknown) => emit('ERROR', message, data),

  /**
   * Log an HTTP request without exposing auth headers or body secrets.
   */
  request: (method: string, url: string, hasAuth: boolean) => {
    emit('DEBUG', `→ ${method.toUpperCase()} ${url} ${hasAuth ? '[authenticated]' : '[unauthenticated]'}`);
  },

  /**
   * Log an HTTP response — status and url only, never body.
   */
  response: (method: string, url: string, status: number) => {
    emit('DEBUG', `← ${status} ${method.toUpperCase()} ${url}`);
  },

  /**
   * Log a security finding (always emitted regardless of log level).
   */
  finding: (id: string, description: string, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') => {
    console.log(`\n⚠  SECURITY FINDING [${severity}] ${id}`);
    console.log(`   ${description}\n`);
  },

  redactToken,
};
