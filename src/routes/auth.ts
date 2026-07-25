import { Hono } from "hono";
import type { AppContext } from "../middleware";
import { checkRateLimit, resetRateLimit, requireSession } from "../middleware";
import { getUserByEmail, getUserByUsername, getUserByIdentifier, nowUnix, uuid, verifyAndConsumeTotp } from "../db";
import {
  hashPassword,
  verifyPassword,
  isPasswordStrongEnough,
  isValidEmailFormat,
  isValidUsername,
  normalizeUsername,
  DUMMY_PASSWORD_HASH,
  generateNetToken,
  hashToken,
} from "../lib/crypto";
import { signShortLivedJwt, verifyShortLivedJwt } from "../lib/jwt";
import { setSessionCookie, clearSessionCookie } from "../lib/session-cookie";

export const authRoutes = new Hono<AppContext>();

const SESSION_DURATION_SECONDS = 60 * 60 * 24 * 7; // 7 jours
const CHALLENGE_2FA_TTL = 60 * 5; // 5 minutes

// ---------------- POST /auth/register ----------------
authRoutes.post("/register", async (c) => {
  const body = await c.req.json().catch(() => null);
  const email = typeof body?.email === "string" ? body.email.toLowerCase().trim() : null;
  const username = typeof body?.username === "string" ? body.username.trim() : null;
  const password = typeof body?.password === "string" ? body.password : null;
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";

  // Anti-spam / anti-bourrage de comptes : limite par IP avant toute autre logique.
  const rateOk = await checkRateLimit(c.env.RATE_LIMIT, `register-ip:${ip}`, 5, 3600);
  if (!rateOk) {
    return c.json({ error: "too_many_requests", message: "Trop de créations de compte, réessayez plus tard." }, 429);
  }

  if (!email || !isValidEmailFormat(email)) {
    return c.json({ error: "bad_request", message: "Adresse e-mail invalide." }, 400);
  }
  if (!username || !isValidUsername(username)) {
    return c.json(
      {
        error: "bad_request",
        message: "Nom d'utilisateur invalide (3 à 32 caractères : lettres, chiffres, _ ou -).",
      },
      400
    );
  }
  if (!password || !isPasswordStrongEnough(password)) {
    return c.json(
      {
        error: "bad_request",
        message: "Mot de passe invalide (10 à 128 caractères, majuscule, minuscule, chiffre).",
      },
      400
    );
  }

  const existingEmail = await getUserByEmail(c.env.DB, email);
  if (existingEmail) {
    return c.json({ error: "conflict", message: "Un compte existe déjà avec cet e-mail." }, 409);
  }
  const usernameNormalized = normalizeUsername(username);
  const existingUsername = await getUserByUsername(c.env.DB, usernameNormalized);
  if (existingUsername) {
    return c.json({ error: "conflict", message: "Ce nom d'utilisateur est déjà pris." }, 409);
  }

  const id = uuid();
  const passwordHash = await hashPassword(password);
  const ts = nowUnix();

  try {
    await c.env.DB.prepare(
      `INSERT INTO users (id, email, username, username_normalized, password_hash, permissions, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 0, ?, ?)`
    )
      .bind(id, email, username, usernameNormalized, passwordHash, ts, ts)
      .run();
  } catch (err: any) {
    // Filet de sécurité en cas de double inscription simultanée (race condition)
    if (String(err?.message ?? "").includes("UNIQUE")) {
      return c.json({ error: "conflict", message: "E-mail ou nom d'utilisateur déjà pris." }, 409);
    }
    throw err;
  }

  return c.json({ id, email, username, message: "Compte créé. Vous pouvez maintenant vous connecter." }, 201);
});

// ---------------- POST /auth/login ----------------
authRoutes.post("/login", async (c) => {
  const body = await c.req.json().catch(() => null);
  // "identifier" accepte indifféremment un e-mail ou un nom d'utilisateur.
  // On garde une compatibilité avec un éventuel champ "email" existant côté front.
  const rawIdentifier =
    typeof body?.identifier === "string"
      ? body.identifier
      : typeof body?.email === "string"
      ? body.email
      : null;
  const identifier = rawIdentifier ? rawIdentifier.trim() : null;
  const password = typeof body?.password === "string" ? body.password : null;
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";

  if (!identifier || !password) {
    return c.json({ error: "bad_request", message: "identifier (e-mail ou pseudo) et mot de passe requis." }, 400);
  }
  if (identifier.length > 254 || password.length > 128) {
    return c.json({ error: "bad_request", message: "Identifiants invalides." }, 400);
  }

  const rateOk = await checkRateLimit(c.env.RATE_LIMIT, `login:${identifier.toLowerCase()}`, 8, 300);
  const rateOkIp = await checkRateLimit(c.env.RATE_LIMIT, `login-ip:${ip}`, 20, 300);
  if (!rateOk || !rateOkIp) {
    return c.json({ error: "too_many_requests", message: "Trop de tentatives, réessayez plus tard." }, 429);
  }

  const user = await getUserByIdentifier(c.env.DB, identifier);
  // Réponse volontairement identique si l'identifiant n'existe pas ou si le mdp est faux (anti-enumération)
  const invalidCreds = () =>
    c.json({ error: "unauthorized", message: "Identifiants invalides." }, 401);

  if (!user) {
    // Anti-timing-attack : on fait quand même tourner un PBKDF2 de même coût
    // que pour un vrai compte, pour que le temps de réponse ne révèle pas
    // si l'identifiant existe ou non.
    await verifyPassword(password, DUMMY_PASSWORD_HASH);
    return invalidCreds();
  }

  const validPassword = await verifyPassword(password, user.password_hash);
  if (!validPassword) return invalidCreds();

  if (user.banned) {
    return c.json({ error: "forbidden", message: "Ce compte est banni.", reason: user.ban_reason }, 403);
  }
  if (user.timeout_until && user.timeout_until > nowUnix()) {
    return c.json(
      { error: "forbidden", message: "Ce compte est en timeout.", until: user.timeout_until },
      403
    );
  }

  await resetRateLimit(c.env.RATE_LIMIT, `login:${identifier.toLowerCase()}`);

  // --- Double authentification activée : on ne délivre pas de session
  // tout de suite, on renvoie un challenge JWT court à valider via /auth/login/2fa ---
  if (user.oauth2_enabled) {
    const challenge = await signShortLivedJwt(
      c.env.JWT_SECRET,
      { sub: user.id, purpose: "2fa_challenge" },
      CHALLENGE_2FA_TTL
    );
    return c.json({ requires_2fa: true, challenge_token: challenge, expires_in: CHALLENGE_2FA_TTL });
  }

  // --- Pas de 2FA : session directe ---
  await createSession(c, user.id, ip);
  return c.json({ requires_2fa: false, message: "Connecté." });
});

// ---------------- POST /auth/login/2fa ----------------
authRoutes.post("/login/2fa", async (c) => {
  const body = await c.req.json().catch(() => null);
  const challengeToken = typeof body?.challenge_token === "string" ? body.challenge_token : null;
  const code = typeof body?.code === "string" ? body.code.trim() : null;
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";

  if (!challengeToken || !code) {
    return c.json({ error: "bad_request", message: "challenge_token et code requis." }, 400);
  }

  const rateOk = await checkRateLimit(c.env.RATE_LIMIT, `2fa:${challengeToken.slice(0, 20)}`, 6, 300);
  if (!rateOk) {
    return c.json({ error: "too_many_requests", message: "Trop de tentatives." }, 429);
  }

  const verified = await verifyShortLivedJwt(c.env.JWT_SECRET, challengeToken, "2fa_challenge");
  if (!verified) {
    return c.json({ error: "unauthorized", message: "Challenge invalide ou expiré." }, 401);
  }

  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?")
    .bind(verified.sub)
    .first<{ id: string; oauth2_secret: string | null; banned: number }>();

  if (!user || !user.oauth2_secret) {
    return c.json({ error: "unauthorized", message: "Configuration 2FA invalide." }, 401);
  }

  let valid = false;
  if (/^\d{6}$/.test(code)) {
    valid = await verifyAndConsumeTotp(c.env.DB, user.id, user.oauth2_secret, code);
  } else {
    // Tentative avec un code de récupération
    valid = await tryConsumeRecoveryCode(c.env.DB, c.env.TOKEN_PEPPER, user.id, code);
  }

  if (!valid) {
    return c.json({ error: "unauthorized", message: "Code invalide." }, 401);
  }

  await createSession(c, user.id, ip);
  return c.json({ message: "Connecté." });
});

// ---------------- POST /auth/logout ----------------
authRoutes.post("/logout", requireSession, async (c) => {
  const tokenHash = c.get("tokenHash");
  await c.env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  clearSessionCookie(c);
  return c.json({ message: "Déconnecté." });
});

// ---------------- Helpers internes ----------------

async function createSession(c: any, userId: string, ip: string): Promise<string> {
  const netToken = generateNetToken();
  const tokenHash = await hashToken(netToken, c.env.TOKEN_PEPPER);
  const ts = nowUnix();
  await c.env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_id, ip, user_agent, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(tokenHash, userId, ip, c.req.header("User-Agent") ?? null, ts, ts + SESSION_DURATION_SECONDS)
    .run();
  // Le token brut ne quitte plus jamais le serveur via le JSON de réponse :
  // il part uniquement dans un cookie httpOnly (voir lib/session-cookie.ts).
  setSessionCookie(c, netToken, SESSION_DURATION_SECONDS);
  return netToken;
}

export async function tryConsumeRecoveryCode(
  db: D1Database,
  pepper: string,
  userId: string,
  code: string
): Promise<boolean> {
  const normalized = code.trim().toUpperCase();
  const codeHash = await hashToken(normalized, pepper);
  const row = await db
    .prepare("SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used = 0")
    .bind(userId, codeHash)
    .first<{ id: string }>();
  if (!row) return false;
  await db.prepare("UPDATE recovery_codes SET used = 1 WHERE id = ?").bind(row.id).run();
  return true;
}
