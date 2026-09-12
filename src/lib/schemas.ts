/**
 * Zod runtime schemas for API response validation.
 *
 * These are used in schema validation tests to assert that responses
 * conform to expected shapes — going beyond status-code-only checks.
 *
 * Security note: schemas document WHICH fields are present. The data
 * exposure tests use these to flag sensitive fields that SHOULD NOT
 * be returned (e.g. password, ssn, cardNumber).
 */

import { z } from 'zod';

// ── Auth ──────────────────────────────────────────────────────────────────────

export const LoginResponseSchema = z.object({
  id: z.number(),
  username: z.string(),
  email: z.string().email(),
  firstName: z.string(),
  lastName: z.string(),
  gender: z.string(),
  image: z.string().url(),
  accessToken: z.string().min(1),
  refreshToken: z.string().min(1),
});

export const RefreshResponseSchema = z.object({
  accessToken: z.string().min(1),
  refreshToken: z.string().min(1),
});

export const AuthMeResponseSchema = z.object({
  id: z.number(),
  username: z.string(),
  email: z.string().email(),
  firstName: z.string(),
  lastName: z.string(),
  gender: z.string(),
  image: z.string(),
});

// ── Users ─────────────────────────────────────────────────────────────────────

/** Minimal user schema — fields that MUST always be present */
export const UserMinimalSchema = z.object({
  id: z.number(),
  firstName: z.string(),
  lastName: z.string(),
  email: z.string().email(),
  username: z.string(),
  role: z.enum(['admin', 'moderator', 'user']),
});

/** Full user schema including optional fields */
export const UserSchema = UserMinimalSchema.extend({
  age: z.number().optional(),
  gender: z.string().optional(),
  phone: z.string().optional(),
  image: z.string().optional(),
  address: z.object({
    address: z.string(),
    city: z.string(),
    state: z.string(),
    country: z.string(),
  }).optional(),
  company: z.object({
    name: z.string(),
    title: z.string(),
    department: z.string(),
  }).optional(),
  // These are documented to be present but represent security findings:
  password: z.string().optional(),  // SECURITY: should not be returned
  ssn: z.string().optional(),       // SECURITY: highly sensitive PII
  ein: z.string().optional(),       // SECURITY: sensitive identifier
  bank: z.object({
    cardNumber: z.string(),         // SECURITY: PCI-sensitive data
    cardExpire: z.string(),
    cardType: z.string(),
    currency: z.string(),
    iban: z.string(),               // SECURITY: sensitive financial data
  }).optional(),
  macAddress: z.string().optional(), // SECURITY: device identifier
  ip: z.string().optional(),         // SECURITY: network identifier
  crypto: z.object({
    coin: z.string(),
    wallet: z.string(),             // SECURITY: financial account identifier
    network: z.string(),
  }).optional(),
});

export const UsersListSchema = z.object({
  users: z.array(UserMinimalSchema),
  total: z.number(),
  skip: z.number(),
  limit: z.number(),
});

export const DeletedUserSchema = UserSchema.extend({
  isDeleted: z.boolean(),
  deletedOn: z.string(),
});

// ── Products ──────────────────────────────────────────────────────────────────

export const ProductSchema = z.object({
  id: z.number(),
  title: z.string(),
  description: z.string(),
  category: z.string(),
  price: z.number().nonnegative(),
  discountPercentage: z.number().nonnegative(),
  rating: z.number().min(0).max(5),
  stock: z.number().nonnegative(),
  tags: z.array(z.string()),
  sku: z.string(),
  thumbnail: z.string(),
  images: z.array(z.string()),
});

export const ProductsListSchema = z.object({
  products: z.array(ProductSchema),
  total: z.number(),
  skip: z.number(),
  limit: z.number(),
});

// ── Carts ─────────────────────────────────────────────────────────────────────

export const CartProductSchema = z.object({
  id: z.number(),
  title: z.string(),
  price: z.number().nonnegative(),
  quantity: z.number().positive(),
  total: z.number().nonnegative(),
  discountPercentage: z.number().nonnegative(),
  discountedTotal: z.number().nonnegative(),
  thumbnail: z.string(),
});

export const CartSchema = z.object({
  id: z.number(),
  products: z.array(CartProductSchema),
  total: z.number().nonnegative(),
  discountedTotal: z.number().nonnegative(),
  userId: z.number(),
  totalProducts: z.number().nonnegative(),
  totalQuantity: z.number().nonnegative(),
});

export const CartsListSchema = z.object({
  carts: z.array(CartSchema),
  total: z.number(),
  skip: z.number(),
  limit: z.number(),
});

// ── Error response ────────────────────────────────────────────────────────────

export const ApiErrorSchema = z.object({
  message: z.string(),
});

// ── Helper ────────────────────────────────────────────────────────────────────

/**
 * Validate a response body against a Zod schema.
 * Returns { success, error } so tests can make rich assertions
 * rather than throwing immediately.
 */
export function validateSchema<T>(
  schema: z.ZodType<T>,
  data: unknown
): { success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(data);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return {
    success: false,
    error: result.error.issues
      .map((i) => `${i.path.join('.')}: ${i.message}`)
      .join('; '),
  };
}
