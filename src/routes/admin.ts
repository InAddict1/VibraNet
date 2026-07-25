import { Hono } from "hono";
import type { AppContext } from "../middleware";
import { requireSession, requirePermission } from "../middleware";
import { getUserById, nowUnix, toAdminUserView } from "../db";
import { PERMISSIONS } from "../permissions";
import { generateRandomPassword, hashPassword } from "../lib/crypto";

export const adminRoutes = new Hono<AppContext>();
adminRoutes.use("*", requireSession);

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

    await c.env.DB.prepare("UPDATE users SET permissions = ?, updated_at = ? WHERE id = ?")
      .bind(permissions, nowUnix(), targetId)
      .run();

    return c.json({ message: "Permissions mises à jour." });
  }
);
