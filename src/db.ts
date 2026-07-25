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
  password_hash: string;
  force_password_change: number;
  permissions: number;
  oauth2_enabled: number;
  oauth2_secret: string | null;
  oauth2_secret_pending: string | null;
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

/** Supprime les champs sensibles avant tout retour au client, quel qu'il soit. */
export function toPublicUser(user: UserRow) {
  return {
    id: user.id,
    email: user.email,
    oauth2_enabled: !!user.oauth2_enabled,
    banned: !!user.banned,
    created_at: user.created_at,
  };
}

/** Vue "admin" : toujours SANS password_hash, secrets 2FA, ni codes de récupération. */
export function toAdminUserView(user: UserRow) {
  return {
    id: user.id,
    email: user.email,
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
