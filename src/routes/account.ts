import { Hono } from "hono";
import type { AppContext } from "../middleware";
import { requireSession } from "../middleware";
import { nowUnix, uuid, verifyAndConsumeTotp, getUserByUsername, toMeView } from "../db";
import {
  hashPassword,
  verifyPassword,
  isPasswordStrongEnough,
  hashToken,
  generateTotpSecret,
  buildOtpAuthUri,
  generateRecoveryCode,
  isValidUsername,
  normalizeUsername,
  isValidAvatarUrl,
} from "../lib/crypto";
import { signShortLivedJwt, verifyShortLivedJwt } from "../lib/jwt";
import { tryConsumeRecoveryCode } from "./auth";

export const accountRoutes = new Hono<AppContext>();
accountRoutes.use("*", requireSession);

const RECOVERY_TOKEN_TTL = 60 * 5; // 5 minutes
const RECOVERY_CODES_COUNT = 10;

// ---------------- GET /account/me ----------------
// Retourne : id, username, email, avatar_url, et net_token UNIQUEMENT pour les
// clients non-navigateur (curl, scripts, apps) qui ne bénéficient pas du
// cookie httpOnly. Un vrai navigateur a déjà la session via le cookie — pas
// besoin (et pas souhaitable) de lui exposer le token en clair dans le JSON.
// ⚠️ Détection par User-Agent = heuristique de confort, pas une garantie de
// sécurité (voir src/lib/client-detection.ts).
accountRoutes.get("/me", async (c) => {
  const user = c.get("user");
  return c.json(toMeView(user));
});

// ---------------- PATCH /account/profile ----------------
// Modifie son propre pseudo et/ou son avatar. Le pseudo doit rester unique
// (insensible à la casse) ; aucun autre champ ne peut être modifié ici.
accountRoutes.patch("/profile", async (c) => {
  const user = c.get("user");
  const body = await c.req.json().catch(() => null);
  const username = typeof body?.username === "string" ? body.username.trim() : undefined;
  const avatarUrl = body?.avatar_url === null ? null : typeof body?.avatar_url === "string" ? body.avatar_url.trim() : undefined;

  if (username === undefined && avatarUrl === undefined) {
    return c.json({ error: "bad_request", message: "Rien à mettre à jour (username et/ou avatar_url)." }, 400);
  }

  let newUsername = user.username;
  let newUsernameNormalized = user.username_normalized;
  if (username !== undefined) {
    if (!isValidUsername(username)) {
      return c.json(
        { error: "bad_request", message: "Nom d'utilisateur invalide (3 à 32 caractères : lettres, chiffres, _ ou -)." },
        400
      );
    }
    const normalized = normalizeUsername(username);
    if (normalized !== user.username_normalized) {
      const existing = await getUserByUsername(c.env.DB, normalized);
      if (existing) {
        return c.json({ error: "conflict", message: "Ce nom d'utilisateur est déjà pris." }, 409);
      }
    }
    newUsername = username;
    newUsernameNormalized = normalized;
  }

  let newAvatarUrl = user.avatar_url;
  if (avatarUrl !== undefined) {
    if (avatarUrl !== null && !isValidAvatarUrl(avatarUrl)) {
      return c.json({ error: "bad_request", message: "URL d'avatar invalide (http/https, 2048 caractères max)." }, 400);
    }
    newAvatarUrl = avatarUrl;
  }

  try {
    await c.env.DB.prepare(
      "UPDATE users SET username = ?, username_normalized = ?, avatar_url = ?, updated_at = ? WHERE id = ?"
    )
      .bind(newUsername, newUsernameNormalized, newAvatarUrl, nowUnix(), user.id)
      .run();
  } catch (err: any) {
    if (String(err?.message ?? "").includes("UNIQUE")) {
      return c.json({ error: "conflict", message: "Ce nom d'utilisateur est déjà pris." }, 409);
    }
    throw err;
  }

  return c.json({
    message: "Profil mis à jour.",
    username: newUsername,
    avatar_url: newAvatarUrl,
  });
});

// ---------------- POST /account/password ----------------
accountRoutes.post("/password", async (c) => {
  const user = c.get("user");
  const body = await c.req.json().catch(() => null);
  const currentPassword = typeof body?.current_password === "string" ? body.current_password : null;
  const newPassword = typeof body?.new_password === "string" ? body.new_password : null;

  if (!currentPassword || !newPassword) {
    return c.json({ error: "bad_request", message: "current_password et new_password requis." }, 400);
  }
  if (currentPassword.length > 128 || newPassword.length > 128) {
    return c.json({ error: "bad_request", message: "Mot de passe trop long (128 caractères max)." }, 400);
  }
  if (!(await verifyPassword(currentPassword, user.password_hash))) {
    return c.json({ error: "unauthorized", message: "Mot de passe actuel incorrect." }, 401);
  }
  if (!isPasswordStrongEnough(newPassword)) {
    return c.json({ error: "bad_request", message: "Nouveau mot de passe trop faible." }, 400);
  }

  const newHash = await hashPassword(newPassword);
  await c.env.DB.prepare(
    "UPDATE users SET password_hash = ?, force_password_change = 0, updated_at = ? WHERE id = ?"
  )
    .bind(newHash, nowUnix(), user.id)
    .run();

  // Sécurité : on révoque toutes les autres sessions actives (garde la courante)
  const currentTokenHash = c.get("tokenHash");
  await c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?")
    .bind(user.id, currentTokenHash)
    .run();

  return c.json({ message: "Mot de passe mis à jour. Les autres sessions ont été déconnectées." });
});

// ---------------- POST /account/oauth2/enable ----------------
// Étape 1: on génère un secret "en attente" et l'URI otpauth pour le QR code.
accountRoutes.post("/oauth2/enable", async (c) => {
  const user = c.get("user");
  const body = await c.req.json().catch(() => null);
  const password = typeof body?.password === "string" ? body.password : null;

  if (!password || password.length > 128 || !(await verifyPassword(password, user.password_hash))) {
    return c.json({ error: "unauthorized", message: "Mot de passe incorrect." }, 401);
  }
  if (user.oauth2_enabled) {
    return c.json({ error: "conflict", message: "La double authentification est déjà activée." }, 409);
  }

  const secret = generateTotpSecret();
  await c.env.DB.prepare("UPDATE users SET oauth2_secret_pending = ?, updated_at = ? WHERE id = ?")
    .bind(secret, nowUnix(), user.id)
    .run();

  return c.json({
    secret,
    otpauth_url: buildOtpAuthUri(secret, user.email),
    message: "Scannez le QR code puis confirmez avec /account/oauth2/confirm.",
  });
});

// ---------------- POST /account/oauth2/confirm ----------------
// Étape 2: l'utilisateur envoie le code généré par son app pour valider.
accountRoutes.post("/oauth2/confirm", async (c) => {
  const user = c.get("user");
  const body = await c.req.json().catch(() => null);
  const code = typeof body?.code === "string" ? body.code.trim() : null;

  if (!user.oauth2_secret_pending) {
    return c.json({ error: "bad_request", message: "Aucune activation 2FA en attente." }, 400);
  }
  if (!code || !(await verifyAndConsumeTotp(c.env.DB, user.id, user.oauth2_secret_pending, code))) {
    return c.json({ error: "unauthorized", message: "Code invalide." }, 401);
  }

  await c.env.DB.prepare(
    `UPDATE users
     SET oauth2_enabled = 1, oauth2_secret = oauth2_secret_pending, oauth2_secret_pending = NULL, updated_at = ?
     WHERE id = ?`
  )
    .bind(nowUnix(), user.id)
    .run();

  const codes = await regenerateRecoveryCodes(c.env.DB, c.env.TOKEN_PEPPER, user.id);

  return c.json({
    message: "Double authentification activée.",
    recovery_codes: codes,
    warning: "Conservez ces codes en lieu sûr : ils ne seront plus jamais affichés sous cette forme.",
  });
});

// ---------------- POST /account/oauth2/disable ----------------
accountRoutes.post("/oauth2/disable", async (c) => {
  const user = c.get("user");
  const body = await c.req.json().catch(() => null);
  const password = typeof body?.password === "string" ? body.password : null;
  const code = typeof body?.code === "string" ? body.code.trim() : null;

  if (!password || password.length > 128 || !(await verifyPassword(password, user.password_hash))) {
    return c.json({ error: "unauthorized", message: "Mot de passe incorrect." }, 401);
  }
  if (!user.oauth2_enabled || !user.oauth2_secret) {
    return c.json({ error: "bad_request", message: "La 2FA n'est pas activée." }, 400);
  }

  let valid = false;
  if (code && /^\d{6}$/.test(code)) {
    valid = await verifyAndConsumeTotp(c.env.DB, user.id, user.oauth2_secret, code);
  } else if (code) {
    valid = await tryConsumeRecoveryCode(c.env.DB, c.env.TOKEN_PEPPER, user.id, code);
  }
  if (!valid) {
    return c.json({ error: "unauthorized", message: "Code de vérification invalide." }, 401);
  }

  await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE users SET oauth2_enabled = 0, oauth2_secret = NULL, oauth2_secret_pending = NULL, updated_at = ? WHERE id = ?"
    ).bind(nowUnix(), user.id),
    c.env.DB.prepare("DELETE FROM recovery_codes WHERE user_id = ?").bind(user.id),
  ]);

  return c.json({ message: "Double authentification désactivée." });
});

// ---------------- POST /account/oauth2/recovery-codes/request ----------------
// L'utilisateur envoie son mot de passe -> reçoit un jeton JWT court pour aller chercher ses codes.
accountRoutes.post("/oauth2/recovery-codes/request", async (c) => {
  const user = c.get("user");
  const body = await c.req.json().catch(() => null);
  const password = typeof body?.password === "string" ? body.password : null;

  if (!password || password.length > 128 || !(await verifyPassword(password, user.password_hash))) {
    return c.json({ error: "unauthorized", message: "Mot de passe incorrect." }, 401);
  }
  if (!user.oauth2_enabled) {
    return c.json({ error: "bad_request", message: "La 2FA n'est pas activée sur ce compte." }, 400);
  }

  const token = await signShortLivedJwt(
    c.env.JWT_SECRET,
    { sub: user.id, purpose: "recovery_reveal" },
    RECOVERY_TOKEN_TTL
  );
  return c.json({ recovery_token: token, expires_in: RECOVERY_TOKEN_TTL });
});

// ---------------- POST /account/oauth2/recovery-codes/reveal ----------------
// ⚠️ Comme les codes sont stockés hashés, cette étape régénère un nouveau
// jeu de 10 codes (les anciens, non utilisés, sont invalidés).
accountRoutes.post("/oauth2/recovery-codes/reveal", async (c) => {
  const user = c.get("user");
  const body = await c.req.json().catch(() => null);
  const recoveryToken = typeof body?.recovery_token === "string" ? body.recovery_token : null;

  if (!recoveryToken) {
    return c.json({ error: "bad_request", message: "recovery_token requis." }, 400);
  }
  const verified = await verifyShortLivedJwt(c.env.JWT_SECRET, recoveryToken, "recovery_reveal");
  if (!verified || verified.sub !== user.id) {
    return c.json({ error: "unauthorized", message: "Jeton invalide ou expiré." }, 401);
  }

  const codes = await regenerateRecoveryCodes(c.env.DB, c.env.TOKEN_PEPPER, user.id);
  return c.json({
    recovery_codes: codes,
    warning: "Les anciens codes non utilisés sont désormais invalides.",
  });
});

// ---------------- Helper ----------------
async function regenerateRecoveryCodes(
  db: D1Database,
  pepper: string,
  userId: string
): Promise<string[]> {
  await db.prepare("DELETE FROM recovery_codes WHERE user_id = ?").bind(userId).run();

  const plainCodes: string[] = [];
  const inserts = [];
  const ts = nowUnix();
  for (let i = 0; i < RECOVERY_CODES_COUNT; i++) {
    const plain = generateRecoveryCode();
    plainCodes.push(plain);
    const hash = await hashToken(plain, pepper);
    inserts.push(
      db
        .prepare("INSERT INTO recovery_codes (id, user_id, code_hash, used, created_at) VALUES (?, ?, ?, 0, ?)")
        .bind(uuid(), userId, hash, ts)
    );
  }
  await db.batch(inserts);
  return plainCodes;
    }
