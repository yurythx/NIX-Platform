package auth

// Roles known to the platform (§31). Keycloak is the source of truth for
// role assignment — these constants exist so authorization checks in code
// don't scatter string literals.
const (
	RoleUser               RoleName = "nix-user"
	RoleAdmin              RoleName = "nix-admin"
	RoleIntegrationManager RoleName = "nix-integration-manager"
	RoleAuditor            RoleName = "nix-auditor"
)

type RoleName = string

// Permission is a fine-grained capability checked by RequirePermission,
// for handlers where "does the caller have one of these roles" isn't
// specific enough. The mapping below is intentionally simple — a single
// static role -> permissions table — and is the extension point if the
// platform later needs per-resource or attribute-based rules.
type Permission string

const (
	PermUsersRead          Permission = "users:read"
	PermUsersManage        Permission = "users:manage"
	PermIntegrationsRead   Permission = "integrations:read"
	PermIntegrationsTest   Permission = "integrations:test"
	PermIntegrationsManage Permission = "integrations:manage"
	PermAuditRead          Permission = "audit:read"
)

// rolePermissions grants nix-admin every permission implicitly (checked
// separately in HasPermission) and gives the other roles the minimum set
// implied by their name in the spec.
var rolePermissions = map[RoleName][]Permission{
	RoleUser: {
		PermUsersRead,
	},
	RoleIntegrationManager: {
		PermIntegrationsRead,
		PermIntegrationsTest,
		PermIntegrationsManage,
	},
	RoleAuditor: {
		PermAuditRead,
		PermUsersRead,
		PermIntegrationsRead,
	},
}

// HasPermission reports whether identity's roles grant permission.
// nix-admin always has every permission.
func HasPermission(identity Identity, permission Permission) bool {
	if identity.HasRole(RoleAdmin) {
		return true
	}
	for _, role := range identity.Roles {
		for _, p := range rolePermissions[role] {
			if p == permission {
				return true
			}
		}
	}
	return false
}
