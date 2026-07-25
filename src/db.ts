import { findTotpCounter } from "./lib/crypto";

export interface Env {
  DB: D1Database;
  RATE_LIMIT: KVNamespace;
  JWT_SECRET: string;
  TOKEN_PEPPER: string;
  ENVIRONMENT: string;
}

export interface UserRow {
  id: string;
  email: string;
  username: string;
  username_normalized: string;
  avatar_url: string | null;
  password_hash: string;
  force_password_change: number;
  permissions: number;
  oauth2_enabled: number;
  oauth2_secret: string | null;
  oauth2_secret_pending: string | null;
  oauth2_last_counter: number | null;
  banned: number;
  ban_reason: string | null;
  timeout_until: number | null;
  created_at: number;
  updated_at: number;
}

export function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

export function uuid(): string {
  return crypto.randomUUID();
}

export async function getUserByEmail(db: D1Database, email: string): Promise<UserRow | null> {
  const row = await db
    .prepare("SELECT * FROM users WHERE email = ?")
    .bind(email.toLowerCase().trim())
    .first<UserRow>();
  return row ?? null;
}

export async function getUserById(db: D1Database, id: string): Promise<UserRow | null> {
  const row = await db.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
  return row ?? null;
}

export async function getUserByUsername(db: D1Database, username: string): Promise<UserRow | null> {
  const row = await db
    .prepare("SELECT * FROM users WHERE username_normalized = ?")
    .bind(username.trim().toLowerCase())
    .first<UserRow>();
  return row ?? null;
}

export async function getUserByIdentifier(db: D1Database, identifier: string): Promise<UserRow | null> {
  const looksLikeEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier);
  return looksLikeEmail ? getUserByEmail(db, identifier) : getUserByUsername(db, identifier);
}

export async function verifyAndConsumeTotp(
  db: D1Database,
  userId: string,
  secret: string,
  code: string
): Promise<boolean> {
  const counter = await findTotpCounter(secret, code);
  if (counter === null) return false;

  const row = await db
    .prepare("SELECT oauth2_last_counter FROM users WHERE id = ?")
    .bind(userId)
    .first<{ oauth2_last_counter: number | null }>();

  if (row?.oauth2_last_counter !== null && row?.oauth2_last_counter !== undefined && counter <= row.oauth2_last_counter) {
    return false; // code déjà utilisé (rejeu)
  }

  await db.prepare("UPDATE users SET oauth2_last_counter = ? WHERE id = ?").bind(counter, userId).run();
  return true;
}

export function toPublicUser(user: UserRow) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    avatar_url: user.avatar_url,
    oauth2_enabled: !!user.oauth2_enabled,
    banned: !!user.banned,
    created_at: user.created_at,
  };
}

export function toMeView(user: UserRow, netToken: string) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    avatar_url: user.avatar_url,
    net_token: netToken,
  };
}

export function toAdminUserView(user: UserRow) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    avatar_url: user.avatar_url,
    permissions: user.permissions,
    oauth2_enabled: !!user.oauth2_enabled,
    banned: !!user.banned,
    ban_reason: user.ban_reason,
    timeout_until: user.timeout_until,
    force_password_change: !!user.force_password_change,
    created_at: user.created_at,
    updated_at: user.updated_at,
  };
}
