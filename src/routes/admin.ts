import { Hono } from "hono";
import type { AppContext } from "../middleware";
import { requireSession, requirePermission } from "../middleware";
import { getUserById, getUserByUsername, nowUnix, toAdminUserView, type UserRow } from "../db";
import { PERMISSIONS, actorOutranks } from "../permissions";
import { generateRandomPassword, hashPassword, isValidUsername, normalizeUsername, isValidAvatarUrl } from "../lib/crypto";

export const adminRoutes = new Hono<AppContext>();
adminRoutes.use("*", requireSession);

/**
 * Anti-escalade de privilèges : un admin ne peut agir (ban/timeout/suppression/
 * reset mdp/désactivation 2FA) que sur une cible dont il couvre TOUTES les
 * permissions. Empêche un admin "BAN_ACCOUNT only" de bannir un admin qui a
 * en plus RESET_PASSWORDS ou ADMIN_VIBRANET, par exemple.
 * Retourne une Response 403 si l'action doit être bloquée, sinon null.
 */
function denyIfOutranked(actor: UserRow, target: UserRow) {
  if (!actorOutranks(actor.permissions, target.permissions)) {
    return { error: "forbidden", message: "Vous ne pouvez pas agir sur un compte ayant des permissions égales ou supérieures aux vôtres." };
  }
  return null;
}

// ---------------- POST /admin/users/:id/timeout ----------------
adminRoutes.post("/users/:id/timeout", requirePermission(PERMISSIONS.TIMEOUT_USER), async (c) => {
  const targetId = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  const durationSeconds = Number(body?.duration_seconds);
  const reason = typeof body?.reason === "string" ? body.reason : null;

  if (!Number.isFinite(durationSeconds) || durationSeconds <= 0) {
    return c.json({ error: "bad_request", message: "duration_seconds (entier positif) requis." }, 400);
  }

  const target = await getUserById(c.env.DB, targetId);
  if (!target) return c.json({ error: "not_found", message: "Utilisateur introuvable." }, 404);
  const denial = denyIfOutranked(c.get("user"), target);
  if (denial) return c.json(denial, 403);

  const until = nowUnix() + durationSeconds;
  await c.env.DB.prepare("UPDATE users SET timeout_until = ?, ban_reason = ?, updated_at = ? WHERE id = ?")
    .bind(until, reason, nowUnix(), targetId)
    .run();

  // Un timeout révoque aussi les sessions actives
  await c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(targetId).run();

  return c.json({ message: "Utilisateur mis en timeout.", until });
});

// ---------------- DELETE /admin/users/:id ----------------
adminRoutes.delete("/users/:id", requirePermission(PERMISSIONS.DELETE_ACCOUNT), async (c) => {
  const targetId = c.req.param("id");
  const target = await getUserById(c.env.DB, targetId);
  if (!target) return c.json({ error: "not_found", message: "Utilisateur introuvable." }, 404);
  const denial = denyIfOutranked(c.get("user"), target);
  if (denial) return c.json(denial, 403);

  await c.env.DB.prepare("DELETE FROM users WHERE id = ?").bind(targetId).run();
  return c.json({ message: "Compte supprimé définitivement." });
});

// ---------------- POST /admin/users/:id/ban ----------------
adminRoutes.post("/users/:id/ban", requirePermission(PERMISSIONS.BAN_ACCOUNT), async (c) => {
  const targetId = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  const reason = typeof body?.reason === "string" ? body.reason : "Non spécifiée";

  const target = await getUserById(c.env.DB, targetId);
  if (!target) return c.json({ error: "not_found", message: "Utilisateur introuvable." }, 404);
  const denial = denyIfOutranked(c.get("user"), target);
  if (denial) return c.json(denial, 403);

  await c.env.DB.prepare("UPDATE users SET banned = 1, ban_reason = ?, updated_at = ? WHERE id = ?")
    .bind(reason, nowUnix(), targetId)
    .run();
  await c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(targetId).run();

  return c.json({ message: "Compte banni." });
});

// ---------------- POST /admin/users/:id/unban ----------------
adminRoutes.post("/users/:id/unban", requirePermission(PERMISSIONS.BAN_ACCOUNT), async (c) => {
  const targetId = c.req.param("id");
  const target = await getUserById(c.env.DB, targetId);
  if (!target) return c.json({ error: "not_found", message: "Utilisateur introuvable." }, 404);
  const denial = denyIfOutranked(c.get("user"), target);
  if (denial) return c.json(denial, 403);

  await c.env.DB.prepare("UPDATE users SET banned = 0, ban_reason = NULL, updated_at = ? WHERE id = ?")
    .bind(nowUnix(), targetId)
    .run();
  return c.json({ message: "Compte débanni." });
});

// ---------------- POST /admin/ips/ban ----------------
adminRoutes.post("/ips/ban", requirePermission(PERMISSIONS.BAN_IP), async (c) => {
  const admin = c.get("user");
  const body = await c.req.json().catch(() => null);
  const ip = typeof body?.ip === "string" ? body.ip.trim() : null;
  const reason = typeof body?.reason === "string" ? body.reason : "Non spécifiée";

  if (!ip) return c.json({ error: "bad_request", message: "ip requis." }, 400);

  await c.env.DB.prepare(
    "INSERT OR REPLACE INTO banned_ips (ip, reason, banned_by, banned_at) VALUES (?, ?, ?, ?)"
  )
    .bind(ip, reason, admin.id, nowUnix())
    .run();

  return c.json({ message: `IP ${ip} bannie.` });
});

// ---------------- POST /admin/ips/unban ----------------
adminRoutes.post("/ips/unban", requirePermission(PERMISSIONS.BAN_IP), async (c) => {
  const body = await c.req.json().catch(() => null);
  const ip = typeof body?.ip === "string" ? body.ip.trim() : null;
  if (!ip) return c.json({ error: "bad_request", message: "ip requis." }, 400);

  await c.env.DB.prepare("DELETE FROM banned_ips WHERE ip = ?").bind(ip).run();
  return c.json({ message: `IP ${ip} débannie.` });
});

// ---------------- POST /admin/users/:id/reset-password ----------------
// Génère un mot de passe temporaire (à transmettre par vos soins à l'utilisateur,
// aucun service d'e-mail n'est inclus dans ce worker).
adminRoutes.post(
  "/users/:id/reset-password",
  requirePermission(PERMISSIONS.RESET_PASSWORDS),
  async (c) => {
    const targetId = c.req.param("id");
    const target = await getUserById(c.env.DB, targetId);
    if (!target) return c.json({ error: "not_found", message: "Utilisateur introuvable." }, 404);
    const denial = denyIfOutranked(c.get("user"), target);
    if (denial) return c.json(denial, 403);

    const tempPassword = generateRandomPassword();
    const hash = await hashPassword(tempPassword);

    await c.env.DB.batch([
      c.env.DB.prepare(
        "UPDATE users SET password_hash = ?, force_password_change = 1, updated_at = ? WHERE id = ?"
      ).bind(hash, nowUnix(), targetId),
      c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(targetId),
    ]);

    return c.json({
      message: "Mot de passe réinitialisé. Transmettez ce mot de passe temporaire à l'utilisateur.",
      temporary_password: tempPassword,
    });
  }
);

// ---------------- POST /admin/users/:id/profile ----------------
// Permet à un administrateur de corriger le pseudo/avatar d'un utilisateur
// (modération de pseudo abusif, support...). Soumis à la même hiérarchie
// anti-escalade que les autres actions admin.
adminRoutes.post(
  "/users/:id/profile",
  requirePermission(PERMISSIONS.ADMIN_VIBRANET),
  async (c) => {
    const targetId = c.req.param("id");
    const body = await c.req.json().catch(() => null);
    const username = typeof body?.username === "string" ? body.username.trim() : undefined;
    const avatarUrl =
      body?.avatar_url === null ? null : typeof body?.avatar_url === "string" ? body.avatar_url.trim() : undefined;

    if (username === undefined && avatarUrl === undefined) {
      return c.json({ error: "bad_request", message: "Rien à mettre à jour (username et/ou avatar_url)." }, 400);
    }

    const target = await getUserById(c.env.DB, targetId);
    if (!target) return c.json({ error: "not_found", message: "Utilisateur introuvable." }, 404);
    const denial = denyIfOutranked(c.get("user"), target);
    if (denial) return c.json(denial, 403);

    let newUsername = target.username;
    let newUsernameNormalized = target.username_normalized;
    if (username !== undefined) {
      if (!isValidUsername(username)) {
        return c.json(
          { error: "bad_request", message: "Nom d'utilisateur invalide (3 à 32 caractères : lettres, chiffres, _ ou -)." },
          400
        );
      }
      const normalized = normalizeUsername(username);
      if (normalized !== target.username_normalized) {
        const existing = await getUserByUsername(c.env.DB, normalized);
        if (existing) return c.json({ error: "conflict", message: "Ce nom d'utilisateur est déjà pris." }, 409);
      }
      newUsername = username;
      newUsernameNormalized = normalized;
    }

    let newAvatarUrl = target.avatar_url;
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
        .bind(newUsername, newUsernameNormalized, newAvatarUrl, nowUnix(), targetId)
        .run();
    } catch (err: any) {
      if (String(err?.message ?? "").includes("UNIQUE")) {
        return c.json({ error: "conflict", message: "Ce nom d'utilisateur est déjà pris." }, 409);
      }
      throw err;
    }

    return c.json({ message: "Profil mis à jour.", username: newUsername, avatar_url: newAvatarUrl });
  }
);

// ---------------- POST /admin/users/:id/oauth2 ----------------
// Permet de forcer la désactivation de la 2FA d'un utilisateur (cas de
// perte de l'appareil / support). L'activation forcée n'est pas possible
// (le secret TOTP doit être scanné par l'utilisateur lui-même).
adminRoutes.post("/users/:id/oauth2", requirePermission(PERMISSIONS.MANAGE_OAUTH2), async (c) => {
  const targetId = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  const enabled = body?.enabled;

  const target = await getUserById(c.env.DB, targetId);
  if (!target) return c.json({ error: "not_found", message: "Utilisateur introuvable." }, 404);
  const denial = denyIfOutranked(c.get("user"), target);
  if (denial) return c.json(denial, 403);

  if (enabled === false) {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "UPDATE users SET oauth2_enabled = 0, oauth2_secret = NULL, oauth2_secret_pending = NULL, updated_at = ? WHERE id = ?"
      ).bind(nowUnix(), targetId),
      c.env.DB.prepare("DELETE FROM recovery_codes WHERE user_id = ?").bind(targetId),
    ]);
    return c.json({ message: "2FA désactivée de force pour cet utilisateur." });
  }

  return c.json(
    {
      error: "bad_request",
      message: "Seule la désactivation forcée (enabled: false) est supportée : l'activation nécessite le scan du QR code par l'utilisateur.",
    },
    400
  );
});

// ---------------- GET /admin/users ----------------
// Vue liste, réservée à ADMIN_VIBRANET. Ne contient jamais password_hash,
// secrets 2FA ou codes de récupération (données privées exclues).
adminRoutes.get("/users", requirePermission(PERMISSIONS.ADMIN_VIBRANET, { allowAdminOverride: false }), async (c) => {
  const limit = Math.min(Number(c.req.query("limit")) || 50, 200);
  const offset = Number(c.req.query("offset")) || 0;

  const { results } = await c.env.DB.prepare(
    "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?"
  )
    .bind(limit, offset)
    .all();

  return c.json({ users: (results ?? []).map((u: any) => toAdminUserView(u)) });
});

// ---------------- GET /admin/users/:id ----------------
adminRoutes.get(
  "/users/:id",
  requirePermission(PERMISSIONS.ADMIN_VIBRANET, { allowAdminOverride: false }),
  async (c) => {
    const target = await getUserById(c.env.DB, c.req.param("id"));
    if (!target) return c.json({ error: "not_found", message: "Utilisateur introuvable." }, 404);
    return c.json({ user: toAdminUserView(target) });
  }
);

// ---------------- POST /admin/users/:id/permissions ----------------
// Réservé au rôle ADMIN_VIBRANET strict (pas d'override par un autre bit).
adminRoutes.post(
  "/users/:id/permissions",
  requirePermission(PERMISSIONS.ADMIN_VIBRANET, { allowAdminOverride: false }),
  async (c) => {
    const targetId = c.req.param("id");
    const body = await c.req.json().catch(() => null);
    const permissions = Number(body?.permissions);

    if (!Number.isInteger(permissions) || permissions < 0) {
      return c.json({ error: "bad_request", message: "permissions (entier positif) requis." }, 400);
    }

    const target = await getUserById(c.env.DB, targetId);
    if (!target) return c.json({ error: "not_found", message: "Utilisateur introuvable." }, 404);

    const admin = c.get("user");
    // On ne peut ni modifier un compte plus privilégié que soi, ni accorder
    // un droit qu'on ne possède pas soi-même (empêche la self-escalade).
    if (!actorOutranks(admin.permissions, target.permissions)) {
      return c.json(
        { error: "forbidden", message: "Vous ne pouvez pas modifier un compte ayant des permissions égales ou supérieures aux vôtres." },
        403
      );
    }
    if (!actorOutranks(admin.permissions, permissions)) {
      return c.json(
        { error: "forbidden", message: "Vous ne pouvez pas accorder une permission que vous ne possédez pas vous-même." },
        403
      );
    }

    await c.env.DB.prepare("UPDATE users SET permissions = ?, updated_at = ? WHERE id = ?")
      .bind(permissions, nowUnix(), targetId)
      .run();

    return c.json({ message: "Permissions mises à jour." });
  }
);
