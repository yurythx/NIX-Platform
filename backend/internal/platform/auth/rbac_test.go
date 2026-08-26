package auth

import "testing"

func TestHasPermission_AdminHasEverything(t *testing.T) {
	admin := Identity{Roles: []string{RoleAdmin}}

	for _, p := range []Permission{PermUsersRead, PermUsersManage, PermIntegrationsRead, PermIntegrationsTest, PermIntegrationsManage, PermAuditRead} {
		if !HasPermission(admin, p) {
			t.Errorf("expected admin to have permission %q", p)
		}
	}
}

func TestHasPermission_RoleGrantsOnlyItsPermissions(t *testing.T) {
	manager := Identity{Roles: []string{RoleIntegrationManager}}

	if !HasPermission(manager, PermIntegrationsTest) {
		t.Error("expected integration manager to have integrations:test")
	}
	if HasPermission(manager, PermUsersManage) {
		t.Error("expected integration manager NOT to have users:manage")
	}
}

func TestHasPermission_NoRolesDeniesEverything(t *testing.T) {
	anon := Identity{}
	if HasPermission(anon, PermUsersRead) {
		t.Error("expected an identity with no roles to have no permissions")
	}
}
