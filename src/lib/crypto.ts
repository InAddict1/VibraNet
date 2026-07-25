// ============================================================
// Primitives crypto - uniquement Web Crypto natif (pas de dépendance
// externe), donc compatible 100% avec le runtime Cloudflare Workers.
// ============================================================

// Le runtime Cloudflare Workers plafonne PBKDF2 à 100 000 itérations.
const PBKDF2_ITERATIONS = 100_000;

// Limites anti-DoS : empêche d'envoyer un mot de passe/email énorme pour
// faire tourner PBKDF2 sur une entrée massive (coût CPU) ou saturer la DB.
export const MAX_EMAIL_LENGTH = 254;
export const MAX_PASSWORD_LENGTH = 128;

// Hash factice au format valide, utilisé pour égaliser le temps de réponse
// de /auth/login quand l'utilisateur n'existe pas (anti-timing-attack).
// Le coût PBKDF2 est le même que pour un vrai hash ; seul le résultat diffère.
export const DUMMY_PASSWORD_HASH = `pbkdf2$${PBKDF2_ITERATIONS}$${"00".repeat(16)}$${"00".repeat(32)}`;

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------------- Mots de passe (PBKDF2-SHA256) ----------------

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toHex(salt)}$${toHex(derived)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = parseInt(parts[1], 10);
  const salt = fromHex(parts[2]);
  const expectedHash = parts[3];

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return timingSafeEqual(toHex(derived), expectedHash);
}

export function isPasswordStrongEnough(password: string): boolean {
  return (
    typeof password === "string" &&
    password.length >= 10 &&
    password.length <= MAX_PASSWORD_LENGTH &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password)
  );
}

export function isValidEmailFormat(email: string): boolean {
  return (
    typeof email === "string" &&
    email.length > 0 &&
    email.length <= MAX_EMAIL_LENGTH &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

// ---------------- Nom d'utilisateur ----------------

export const MIN_USERNAME_LENGTH = 3;
export const MAX_USERNAME_LENGTH = 32;
export const MAX_AVATAR_URL_LENGTH = 2048;

/** Lettres, chiffres, tiret et underscore uniquement, 3 à 32 caractères. */
export function isValidUsername(username: string): boolean {
  return (
    typeof username === "string" &&
    new RegExp(`^[a-zA-Z0-9_-]{${MIN_USERNAME_LENGTH},${MAX_USERNAME_LENGTH}}$`).test(username)
  );
}

/** Version normalisée (minuscules) utilisée pour garantir l'unicité et le login par pseudo. */
export function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

export function isValidAvatarUrl(url: string): boolean {
  if (typeof url !== "string" || url.length === 0 || url.length > MAX_AVATAR_URL_LENGTH) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

// ---------------- Tokens opaques (net-token, 64 caractères) ----------------

export function generateNetToken(): string {
  // 32 octets -> 64 caractères hexadécimaux
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return toHex(bytes);
}

export async function hashToken(token: string, pepper: string): Promise<string> {
  const data = new TextEncoder().encode(token + pepper);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
}

export function generateRandomPassword(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  // Base64 URL-safe, garanti de contenir maj/min/chiffres dans l'immense majorité des cas
  return "Tmp-" + toHex(bytes).slice(0, 16) + "-Aa1";
}

export function generateRecoveryCode(): string {
  // format lisible: XXXX-XXXX-XXXX
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  const hex = toHex(bytes).toUpperCase();
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}`;
}

export { toHex, fromHex, timingSafeEqual };

// ---------------- TOTP (RFC 6238) - authenticator app ----------------

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function generateTotpSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return base32Encode(bytes);
}

function base32Encode(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/=+$/, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function hotp(secretBase32: string, counter: number, digits = 6): Promise<string> {
  const key = base32Decode(secretBase32);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  // JS ne gère que 32 bits pour les bitshifts, on écrit en 2 parties de 32 bits
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBuf));

  const offset = signature[signature.length - 1] & 0x0f;
  const binCode =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);

  const otp = (binCode % 10 ** digits).toString().padStart(digits, "0");
  return otp;
}

export async function generateTotp(secretBase32: string, timeStepSeconds = 30): Promise<string> {
  const counter = Math.floor(Date.now() / 1000 / timeStepSeconds);
  return hotp(secretBase32, counter);
}

/**
 * Recherche le compteur TOTP correspondant au code fourni, en tolérant une
 * fenêtre de +/- 1 pas de temps (dérive d'horloge). Retourne le compteur
 * exact si trouvé (à utiliser pour l'anti-rejeu), sinon null.
 */
export async function findTotpCounter(
  secretBase32: string,
  token: string,
  timeStepSeconds = 30,
  window = 1
): Promise<number | null> {
  if (!/^\d{6}$/.test(token)) return null;
  const counter = Math.floor(Date.now() / 1000 / timeStepSeconds);
  for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
    const candidate = await hotp(secretBase32, counter + errorWindow);
    if (timingSafeEqual(candidate, token)) return counter + errorWindow;
  }
  return null;
}

/**
 * Vérifie un code TOTP SANS protection anti-rejeu (utilisable seulement
 * pour des vérifications ponctuelles hors flux d'authentification, ex:
 * tests). Préférer `findTotpCounter` + comparaison au dernier compteur
 * consommé (voir `verifyAndConsumeTotp` dans db.ts) partout ailleurs.
 */
export async function verifyTotp(
  secretBase32: string,
  token: string,
  timeStepSeconds = 30,
  window = 1
): Promise<boolean> {
  return (await findTotpCounter(secretBase32, token, timeStepSeconds, window)) !== null;
}

export function buildOtpAuthUri(secretBase32: string, email: string, issuer = "VibraNet"): string {
  const label = encodeURIComponent(`${issuer}:${email}`);
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&digits=6&period=30`;
}
