import { SignJWT, jwtVerify, errors as joseErrors } from "jose";

/**
 * Les JWT ici ne servent QUE pour des flux courts et intermédiaires :
 *  - challenge 2FA après vérification du mot de passe
 *  - jeton de révélation des codes de récupération
 * La session "longue durée" utilisée sur les endpoints protégés est le
 * net-token opaque (voir lib/crypto.ts + middleware.ts), stocké hashé en D1
 * et donc révocable immédiatement (contrairement à un JWT classique).
 */

export type JwtPurpose = "2fa_challenge" | "recovery_reveal";

export async function signShortLivedJwt(
  secret: string,
  payload: { sub: string; purpose: JwtPurpose },
  expiresInSeconds: number
): Promise<string> {
  const key = new TextEncoder().encode(secret);
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + expiresInSeconds)
    .setIssuer("vibranet-api")
    .sign(key);
}

export async function verifyShortLivedJwt(
  secret: string,
  token: string,
  expectedPurpose: JwtPurpose
): Promise<{ sub: string } | null> {
  try {
    const key = new TextEncoder().encode(secret);
    const { payload } = await jwtVerify(token, key, { issuer: "vibranet-api" });
    if (payload.purpose !== expectedPurpose || typeof payload.sub !== "string") return null;
    return { sub: payload.sub };
  } catch (err) {
    if (err instanceof joseErrors.JOSEError) return null;
    return null;
  }
}
