/**
 * ⚠️ Détection HEURISTIQUE, PAS une barrière de sécurité.
 *
 * Basée uniquement sur le User-Agent (aucun fingerprinting canvas/WebGL/audio
 * — ces techniques sont de toute façon bloquées ou faussées par de nombreux
 * navigateurs et ne sont pas fiables). Un attaquant déterminé peut usurper
 * n'importe quel User-Agent (`curl -A "Mozilla/5.0 ..."`) et obtenir le même
 * traitement qu'un vrai navigateur — cette fonction ne doit donc JAMAIS être
 * utilisée pour une décision de sécurité (auth, permissions, etc.).
 *
 * Son seul rôle : éviter d'exposer inutilement `net_token` dans le corps JSON
 * quand un vrai navigateur fait la requête (le cookie httpOnly suffit alors),
 * tout en le laissant disponible pour les clients non-navigateur (curl, wget,
 * scripts, Postman, apps mobiles) qui n'ont pas d'autre moyen de le récupérer.
 * La vraie protection contre le vol de token via JS reste le cookie httpOnly,
 * pas cette détection.
 */

// Signatures de clients non-navigateur les plus courants.
const NON_BROWSER_UA_SIGNATURES = [
  "curl/",
  "wget/",
  "python-requests/",
  "postmanruntime/",
  "insomnia/",
  "httpie/",
  "axios/",
  "node-fetch",
  "go-http-client",
  "okhttp",
  "java/",
  "libwww-perl",
  "python-urllib",
  "aiohttp/",
  "restsharp",
  "dart/",
  "ktor-client",
];

export function isLikelyBrowser(userAgent: string | undefined | null): boolean {
  if (!userAgent) return false; // pas de UA du tout = clairement pas un navigateur
  const ua = userAgent.toLowerCase();
  if (NON_BROWSER_UA_SIGNATURES.some((sig) => ua.includes(sig))) return false;
  // Quasi tous les navigateurs (Chrome, Firefox, Safari, Edge, WebViews mobiles) incluent "mozilla/"
  return ua.includes("mozilla/");
}

/**
 * Version renforcée : combine le User-Agent avec les "Fetch Metadata Request
 * Headers" (Sec-Fetch-Mode / Sec-Fetch-Site). Ces headers sont ajoutés
 * automatiquement par tous les navigateurs modernes sur CHAQUE requête
 * fetch()/XHR/navigation, et le JavaScript de la page NE PEUT PAS les
 * définir ou les falsifier lui-même (forbidden header names bloqués par le
 * navigateur) — contrairement au User-Agent, qu'un simple `curl -A "..."`
 * peut usurper facilement. Un seul des deux signaux positif suffit.
 */
export function isLikelyBrowserRequest(headers: {
  userAgent?: string | null;
  secFetchMode?: string | null;
  secFetchSite?: string | null;
}): boolean {
  if (headers.secFetchMode || headers.secFetchSite) return true;
  return isLikelyBrowser(headers.userAgent);
}
