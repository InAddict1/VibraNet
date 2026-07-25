import type { Context } from "hono";
import { setCookie, deleteCookie } from "hono/cookie";

/**
 * Nom du cookie de session. On évite volontairement "net_token" pour ne pas
 * donner d'indice sur le format du token, et pour ne pas entrer en conflit
 * avec l'ancien header `net-token` qui n'existe plus côté client.
 */
export const SESSION_COOKIE_NAME = "vn_session";

/**
 * Dépose le token de session dans un cookie httpOnly + Secure + SameSite.
 *
 * - httpOnly : le JavaScript de la page (donc du site chargé dans la
 *   WebView) ne peut pas lire ce cookie via `document.cookie`. Un XSS sur le
 *   front-end ne peut donc plus exfiltrer le token de session.
 * - secure   : jamais envoyé en clair, uniquement en HTTPS.
 * - sameSite : "None" est nécessaire ici car le front-end et cette API
 *   Cloudflare Workers sont sur des origines différentes (le README précise
 *   que le front-end est géré séparément) — le navigateur/WebView doit
 *   pouvoir envoyer le cookie sur des requêtes fetch() cross-origin vers
 *   l'API. "None" exige obligatoirement `secure: true` (sinon le navigateur
 *   rejette silencieusement le cookie).
 *   -> Si un jour le front-end est servi depuis le même domaine que l'API
 *      (même origine), passer à "Lax" est préférable (protection CSRF plus
 *      forte, plus besoin de "None").
 *
 * Comme le cookie est httpOnly, le CORS doit explicitement autoriser les
 * credentials (`credentials: true` côté serveur + `credentials: "include"`
 * côté fetch client) et ne JAMAIS refléter "*" comme origine autorisée —
 * voir index.ts.
 */
export function setSessionCookie(c: Context<any>, token: string, maxAgeSeconds: number) {
  setCookie(c, SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    maxAge: maxAgeSeconds,
  });
}

/** Supprime le cookie de session (déconnexion). */
export function clearSessionCookie(c: Context<any>) {
  deleteCookie(c, SESSION_COOKIE_NAME, {
    path: "/",
    secure: true,
    sameSite: "None",
  });
}
