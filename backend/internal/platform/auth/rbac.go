package auth

// Roles conhecidos pela plataforma (§31). O Keycloak é a fonte da verdade
// para a atribuição de roles a usuários — estas constantes existem só para
// que as checagens de autorização no código não espalhem strings literais
// (evitando erro de digitação silencioso em um "nix-admn" em algum lugar).
const (
	RoleUser               RoleName = "nix-user"
	RoleAdmin              RoleName = "nix-admin"
	RoleIntegrationManager RoleName = "nix-integration-manager"
	RoleAuditor            RoleName = "nix-auditor"
)

type RoleName = string

// Permission é uma capacidade granular verificada por RequirePermission,
// para handlers em que "o chamador tem um destes roles" não é específico
// o bastante. O mapeamento abaixo é deliberadamente simples — uma única
// tabela estática role -> permissões — e é o ponto de extensão caso a
// plataforma precise no futuro de regras por recurso ou baseadas em
// atributos (attribute-based access control).
type Permission string

const (
	PermUsersRead          Permission = "users:read"
	PermUsersManage        Permission = "users:manage"
	PermIntegrationsRead   Permission = "integrations:read"
	PermIntegrationsTest   Permission = "integrations:test"
	PermIntegrationsManage Permission = "integrations:manage"
	PermAuditRead          Permission = "audit:read"
)

// rolePermissions concede ao nix-admin toda permissão implicitamente
// (verificado à parte em HasPermission) e dá aos demais roles o conjunto
// mínimo implicado pelo próprio nome, conforme a especificação — ex.: um
// "nix-auditor" só pode ler (audit, users, integrations), nunca escrever.
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

// HasPermission reporta se os roles de identity concedem permission.
// nix-admin sempre tem toda permissão, independente do mapa acima.
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
