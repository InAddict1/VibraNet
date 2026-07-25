import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { cors } from "hono/cors";
import type { AppContext } from "./middleware";
import { ipBanGuard } from "./middleware";
import { authRoutes } from "./routes/auth";
import { accountRoutes } from "./routes/account";
import { adminRoutes } from "./routes/admin";

const app = new Hono<AppContext>();

// ---------------- Sécurité globale ----------------
app.use("*", secureHeaders());
app.use(
  "*",
  cors({
    origin: (origin, c) => {
      const allowed = (c.env as any)?.ALLOWED_ORIGIN;
      if (!allowed) return origin ?? undefined; // fallback permissif si non configuré (dev uniquement)
      return origin === allowed ? origin : undefined;
    },
    credentials: true,
    allowHeaders: ["Content-Type", "net-token", "x-vibranet-csrf"],
    allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    maxAge: 600,
  })
);
app.use("*", ipBanGuard);

// ---------------- Routes ----------------
app.route("/auth", authRoutes);
app.route("/account", accountRoutes);
app.route("/admin", adminRoutes);

app.get("/", (c) => c.json({ name: "VibraNet API", status: "online" }));

app.notFound((c) => c.json({ error: "not_found", message: "Endpoint inconnu." }, 404));

app.onError((err, c) => {
  console.error("Erreur non gérée:", err);

  // ⚠️ DEBUG TEMPORAIRE — à retirer une fois le problème résolu.
  if (c.req.header("x-debug") === "vibranet-debug-2026") {
    return c.json(
      {
        error: "internal_error",
        debug_message: err instanceof Error ? err.message : String(err),
        debug_stack: err instanceof Error ? err.stack : null,
      },
      500
    );
  }

  return c.json({ error: "internal_error", message: "Une erreur interne est survenue." }, 500);
});

export default app;
