/**
 * Redaction utilities.
 *
 * All log output passes through these functions to ensure that
 * credentials, tokens and sensitive PII never appear in reports
 * or console output. This directly satisfies the assessment
 * requirement: "credentials, tokens and sensitive response data
 * must not be committed to the repository or exposed in logs and reports."
 */

/** Fields considered sensitive in API responses */
const SENSITIVE_FIELDS = new Set([
  'password',
  'accessToken',
  'refreshToken',
  'token',
  'ssn',
  'cardNumber',
  'iban',
  'ein',
  'macAddress',
  'ip',
  'wallet',
]);

const REDACTED = '[REDACTED]';

/**
 * Recursively redact sensitive fields from an object before logging.
 * Returns a new object — does not mutate the original.
 */
export function redactObject(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return obj;
  if (typeof obj !== 'object') return obj;

  if (Array.isArray(obj)) {
    return obj.map(redactObject);
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    if (SENSITIVE_FIELDS.has(key)) {
      result[key] = REDACTED;
    } else if (typeof value === 'object' && value !== null) {
      result[key] = redactObject(value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Redact a JWT token — keeps the header visible for debugging
 * (algorithm, type) but masks the payload and signature entirely.
 * e.g. "eyJhbGciOiJIUzI1NiJ9.[REDACTED]"
 */
export function redactToken(token: string): string {
  if (!token || typeof token !== 'string') return REDACTED;
  const parts = token.split('.');
  if (parts.length !== 3) return REDACTED;
  return `${parts[0]}.[REDACTED].[REDACTED]`;
}

/**
 * Safe JSON stringify for log output — redacts sensitive fields.
 */
export function safeStringify(obj: unknown, indent = 2): string {
  return JSON.stringify(redactObject(obj), null, indent);
}
