import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { cors } from "hono/cors";
import type { AppContext } from "./middleware";
import { ipBanGuard } from "./middleware";
import { authRoutes } from "./routes/auth";
import { accountRoutes } from "./routes/account";
import { adminRoutes } from "./routes/admin";

const app = new Hono<AppContext>();

app.use("*", secureHeaders());
app.use(
  "*",
  cors({
    origin: (origin) => origin ?? "vibranet.codeberg.page",
    credentials: true, // requis pour que le navigateur envoie/accepte le cookie httpOnly cross-origin
    allowHeaders: ["Content-Type"],
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    maxAge: 600,
  })
);
app.use("*", ipBanGuard);

app.route("/auth", authRoutes);
app.route("/account", accountRoutes);
app.route("/admin", adminRoutes);

app.get("/", (c) => c.json({ name: "VibraNet API", status: "online" }));

app.notFound((c) => c.json({ error: "not_found", message: "Endpoint inconnu." }, 404));

app.onError((err, c) => {
  console.error("Erreur non gérée:", err);
  return c.json({ error: "internal_error", message: "Une erreur interne est survenue." }, 500);
});

export default app;});

export default app;
