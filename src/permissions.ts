/**
 * Système de permissions hiérarchique basé sur un bitmask (integer).
 * ⚠️ Ces valeurs et le champ `permissions` d'un utilisateur ne sont
 * JAMAIS renvoyés au client (ni dans /auth/login, ni /account/*).
 * Ils ne servent qu'au contrôle d'accès côté serveur.
 */
export const PERMISSIONS = {
  TIMEOUT_USER:     1 << 0, // 1   - timeout un utilisateur
  DELETE_ACCOUNT:   1 << 1, // 2   - supprimer un compte
  BAN_ACCOUNT:      1 << 2, // 4   - bannir un compte
  BAN_IP:           1 << 3, // 8   - bannir une IP
  RESET_PASSWORDS:  1 << 4, // 16  - réinitialiser les mots de passe
  MANAGE_OAUTH2:    1 << 5, // 32  - activer/désactiver la 2FA d'un utilisateur
  ADMIN_VIBRANET:   1 << 6, // 64  - accès à tout, SAUF données privées utilisateurs
} as const;

export type PermissionBit = typeof PERMISSIONS[keyof typeof PERMISSIONS];

/**
 * Vérifie qu'un utilisateur possède une permission donnée.
 * ADMIN_VIBRANET fait office de "super rôle" qui couvre les autres bits,
 * mais ne donne jamais accès aux endpoints marqués `privateData: true`
 * (ex: consultation des secrets 2FA, hash de mot de passe, etc.)
 */
export function hasPermission(
  userPermissions: number,
  required: PermissionBit,
  options: { allowAdminOverride?: boolean } = {}
): boolean {
  const { allowAdminOverride = true } = options;
  const hasDirect = (userPermissions & required) === required;
  if (hasDirect) return true;
  if (allowAdminOverride) {
    return (userPermissions & PERMISSIONS.ADMIN_VIBRANET) === PERMISSIONS.ADMIN_VIBRANET;
  }
  return false;
}
