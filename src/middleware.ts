import type { Context, Next } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import type { Env, UserRow } from "./db";
import { getUserById, nowUnix } from "./db";
import { hashToken } from "./lib/crypto";
import { hasPermission, type PermissionBit } from "./permissions";

export type AppContext = { Bindings: Env; Variables: { user: UserRow; tokenHash: string; token: string } };

export const NET_TOKEN_COOKIE_NAME = "net_token";
// Header custom exigé quand l'authentification provient UNIQUEMENT du cookie
// (pas de header net-token explicite). Un <form> HTML classique ou une image
// cross-site ne peuvent pas définir de header personnalisé : ça bloque le
// CSRF basique même si le cookie est envoyé automatiquement par le navigateur.
export const CSRF_HEADER_NAME = "x-vibranet-csrf";

/**
 * Pose le net-token dans un cookie HttpOnly + Secure + SameSite.
 * HttpOnly empêche tout accès en JavaScript côté site (document.cookie ne
 * le montrera jamais), Secure impose HTTPS, SameSite=Lax bloque son envoi
 * sur des requêtes cross-site (donc la plupart des CSRF) tout en le laissant
 * fonctionner normalement pour votre propre front-end.
 */
export function setSessionCookie(c: Context<AppContext>, token: string, maxAgeSeconds: number) {
  setCookie(c, NET_TOKEN_COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: maxAgeSeconds,
  });
}

export function clearSessionCookie(c: Context<AppContext>) {
  deleteCookie(c, NET_TOKEN_COOKIE_NAME, { path: "/" });
}

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
 * Exige un net-token valide (header `net-token`), résout la session en
 * base, vérifie qu'elle n'est pas expirée, et injecte l'utilisateur dans
 * le contexte (c.get("user")).
 */
export async function requireSession(c: Context<AppContext>, next: Next) {
  const headerToken = c.req.header("net-token");
  const cookieToken = getCookie(c, NET_TOKEN_COOKIE_NAME);
  const token = headerToken || cookieToken;

  if (!token || token.length !== 64) {
    return c.json({ error: "unauthorized", message: "Session manquante (header net-token ou cookie)." }, 401);
  }

  // Anti-CSRF : si le token ne vient QUE du cookie (envoyé automatiquement
  // par le navigateur sur toute requête), on exige un header personnalisé
  // que seul du JS de confiance (fetch/XHR same-site) peut poser.
  if (!headerToken && c.req.header(CSRF_HEADER_NAME) !== "1") {
    return c.json(
      { error: "forbidden", message: `Header anti-CSRF manquant (${CSRF_HEADER_NAME}: 1).` },
      403
    );
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
  c.set("token", token);
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
