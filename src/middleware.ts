import type { Context, Next } from "hono";
import { getCookie } from "hono/cookie";
import type { Env, UserRow } from "./db";
import { getUserById, nowUnix } from "./db";
import { hashToken } from "./lib/crypto";
import { SESSION_COOKIE_NAME } from "./lib/session-cookie";
import { hasPermission, type PermissionBit } from "./permissions";

export type AppContext = { Bindings: Env; Variables: { user: UserRow; tokenHash: string } };

/**
 * Bloque toute requête provenant d'une IP bannie (BAN_IP).
 * Placé en tout premier dans la chaîne de middlewares globaux.
 */
export async function ipBanGuard(c: Context<AppContext>, next: Next) {
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
  if (ip !== "unknown") {
    const banned = await c.env.DB.prepare("SELECT ip FROM banned_ips WHERE ip = ?").bind(ip).first();
    if (banned) {
      return c.json({ error: "forbidden", message: "Cette adresse IP est bannie de VibraNet." }, 403);
    }
  }
  await next();
}

/**
 * Exige une session valide. Le token n'est plus lu depuis un header
 * `net-token` envoyé par le JS du site, mais depuis le cookie httpOnly
 * `vn_session` déposé par /auth/login (voir lib/session-cookie.ts) : le
 * navigateur/WebView l'attache automatiquement, et le JS de la page ne peut
 * ni le lire ni le falsifier.
 */
export async function requireSession(c: Context<AppContext>, next: Next) {
  const token = getCookie(c, SESSION_COOKIE_NAME);
  if (!token || token.length !== 64) {
    return c.json({ error: "unauthorized", message: "Session manquante ou invalide." }, 401);
  }

  const tokenHash = await hashToken(token, c.env.TOKEN_PEPPER);
  const session = await c.env.DB.prepare(
    "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?"
  )
    .bind(tokenHash)
    .first<{ user_id: string; expires_at: number }>();

  if (!session || session.expires_at < nowUnix()) {
    return c.json({ error: "unauthorized", message: "Session expirée ou invalide." }, 401);
  }

  const user = await getUserById(c.env.DB, session.user_id);
  if (!user) {
    return c.json({ error: "unauthorized", message: "Compte introuvable." }, 401);
  }
  if (user.banned) {
    return c.json({ error: "forbidden", message: "Ce compte est banni." }, 403);
  }
  if (user.timeout_until && user.timeout_until > nowUnix()) {
    return c.json(
      { error: "forbidden", message: "Ce compte est temporairement en timeout.", until: user.timeout_until },
      403
    );
  }

  // Un mot de passe réinitialisé par un admin doit être changé avant toute
  // autre action (on n'autorise que le changement de mdp et la déconnexion).
  const path = c.req.path;
  const allowedWhileForced = path === "/account/password" || path === "/auth/logout";
  if (user.force_password_change && !allowedWhileForced) {
    return c.json(
      {
        error: "forbidden",
        message: "Vous devez changer votre mot de passe avant de continuer (POST /account/password).",
        force_password_change: true,
      },
      403
    );
  }

  c.set("user", user);
  c.set("tokenHash", tokenHash);
  await next();
}

/**
 * Middleware factory: exige que l'utilisateur authentifié possède la
 * permission donnée (bitmask backend uniquement). Renvoie 403 sinon.
 */
export function requirePermission(bit: PermissionBit, options?: { allowAdminOverride?: boolean }) {
  return async (c: Context<AppContext>, next: Next) => {
    const user = c.get("user");
    if (!user || !hasPermission(user.permissions, bit, options)) {
      return c.json({ error: "forbidden", message: "Permission insuffisante pour cette action." }, 403);
    }
    await next();
  };
}

/**
 * Rate limiting basique sur KV : bloque après `maxAttempts` échecs dans
 * la fenêtre `windowSeconds`, par identifiant (email ou IP).
 */
export async function checkRateLimit(
  kv: KVNamespace,
  identifier: string,
  maxAttempts = 5,
  windowSeconds = 300
): Promise<boolean> {
  const key = `ratelimit:${identifier}`;
  const raw = await kv.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  if (count >= maxAttempts) return false;
  await kv.put(key, String(count + 1), { expirationTtl: windowSeconds });
  return true;
}

export async function resetRateLimit(kv: KVNamespace, identifier: string): Promise<void> {
  await kv.delete(`ratelimit:${identifier}`);
}
