/**
 * TypeScript interfaces mirroring DummyJSON API response shapes.
 * Used by the API client layer and Zod schemas for runtime validation.
 */

// ── Auth ──────────────────────────────────────────────────────────────────────

export interface LoginResponse {
  id: number;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  gender: string;
  image: string;
  accessToken: string;
  refreshToken: string;
}

export interface RefreshResponse {
  accessToken: string;
  refreshToken: string;
}

export interface AuthMeResponse {
  id: number;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  gender: string;
  image: string;
  role?: string;
}

// ── Users ─────────────────────────────────────────────────────────────────────

export type UserRole = 'admin' | 'moderator' | 'user';

export interface BankInfo {
  cardExpire: string;
  cardNumber: string;
  cardType: string;
  currency: string;
  iban: string;
}

export interface Address {
  address: string;
  city: string;
  state: string;
  stateCode: string;
  postalCode: string;
  coordinates: { lat: number; lng: number };
  country: string;
}

export interface User {
  id: number;
  firstName: string;
  lastName: string;
  maidenName?: string;
  age: number;
  gender: string;
  email: string;
  phone: string;
  username: string;
  password?: string; // NOTE: exposed by API - security finding
  birthDate: string;
  image: string;
  bloodGroup?: string;
  height?: number;
  weight?: number;
  eyeColor?: string;
  hair?: { color: string; type: string };
  ip?: string;
  address?: Address;
  macAddress?: string;
  university?: string;
  bank?: BankInfo;
  company?: {
    department: string;
    name: string;
    title: string;
    address?: Address;
  };
  ein?: string;
  ssn?: string; // NOTE: highly sensitive PII - security finding
  userAgent?: string;
  crypto?: { coin: string; wallet: string; network: string };
  role: UserRole;
}

export interface UsersListResponse {
  users: User[];
  total: number;
  skip: number;
  limit: number;
}

export interface DeletedUser extends User {
  isDeleted: boolean;
  deletedOn: string;
}

// ── Products ──────────────────────────────────────────────────────────────────

export interface Product {
  id: number;
  title: string;
  description: string;
  category: string;
  price: number;
  discountPercentage: number;
  rating: number;
  stock: number;
  tags: string[];
  brand?: string;
  sku: string;
  thumbnail: string;
  images: string[];
}

export interface ProductsListResponse {
  products: Product[];
  total: number;
  skip: number;
  limit: number;
}

// ── Carts ─────────────────────────────────────────────────────────────────────

export interface CartProduct {
  id: number;
  title: string;
  price: number;
  quantity: number;
  total: number;
  discountPercentage: number;
  discountedTotal: number;
  thumbnail: string;
}

export interface Cart {
  id: number;
  products: CartProduct[];
  total: number;
  discountedTotal: number;
  userId: number;
  totalProducts: number;
  totalQuantity: number;
}

export interface CartsListResponse {
  carts: Cart[];
  total: number;
  skip: number;
  limit: number;
}

// ── Todos ─────────────────────────────────────────────────────────────────────

export interface Todo {
  id: number;
  todo: string;
  completed: boolean;
  userId: number;
}

export interface TodosListResponse {
  todos: Todo[];
  total: number;
  skip: number;
  limit: number;
}

// ── Posts ─────────────────────────────────────────────────────────────────────

export interface Post {
  id: number;
  title: string;
  body: string;
  userId: number;
  tags: string[];
  reactions: { likes: number; dislikes: number };
}

export interface PostsListResponse {
  posts: Post[];
  total: number;
  skip: number;
  limit: number;
}

// ── Error responses ───────────────────────────────────────────────────────────

export interface ApiError {
  message: string;
  name?: string;
  status?: number;
}

// ── Auth context (internal) ───────────────────────────────────────────────────

export interface AuthContext {
  userId: number;
  username: string;
  role: UserRole;
  accessToken: string;
  refreshToken: string;
}
