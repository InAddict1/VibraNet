export const PERMISSIONS = {
  TIMEOUT_USER:     1 << 0, // 1   - timeout un utilisateur
  DELETE_ACCOUNT:   1 << 1, // 2   - supprimer un compte
  BAN_ACCOUNT:      1 << 2, // 4   - bannir un compte
  BAN_IP:           1 << 3, // 8   - bannir une IP
  RESET_PASSWORDS:  1 << 4, // 16  - réinitialiser les mots de passe
  MANAGE_OAUTH2:    1 << 5, // 32  - activer/désactiver la 2FA d'un utilisateur
  ADMIN_VIBRANET:   1 << 6, // 64  - accès à tout, SAUF données privées utilisateurs
  ALL:              127,    // somme de tous les bits ci-dessus
} as const;

export type PermissionBit = typeof PERMISSIONS[keyof typeof PERMISSIONS];

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

export function actorOutranks(actorPermissions: number, targetOrGrantedPermissions: number): boolean {
  return (actorPermissions & targetOrGrantedPermissions) === targetOrGrantedPermissions;
}
