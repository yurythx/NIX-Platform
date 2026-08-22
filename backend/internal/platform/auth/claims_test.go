package auth

import (
	"reflect"
	"sort"
	"testing"
)

func TestToIdentity_MergesRealmAndClientRoles(t *testing.T) {
	claims := accessTokenClaims{
		Subject:           "sub-123",
		PreferredUsername: "jdoe",
		Email:             "jdoe@example.com",
		RealmAccess:       roleContainer{Roles: []string{"nix-user", "offline_access"}},
		ResourceAccess: map[string]roleContainer{
			"nix-platform-api": {Roles: []string{"nix-integration-manager"}},
			"other-client":     {Roles: []string{"should-not-appear"}},
		},
	}

	identity := claims.toIdentity("nix-platform-api")

	if identity.Subject != "sub-123" {
		t.Errorf("Subject = %q", identity.Subject)
	}
	if identity.Username != "jdoe" {
		t.Errorf("Username = %q", identity.Username)
	}
	if identity.Email != "jdoe@example.com" {
		t.Errorf("Email = %q", identity.Email)
	}

	got := append([]string{}, identity.Roles...)
	sort.Strings(got)
	want := []string{"nix-integration-manager", "nix-user", "offline_access"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Roles = %v, want %v", got, want)
	}
}

func TestToIdentity_DeduplicatesRoles(t *testing.T) {
	claims := accessTokenClaims{
		RealmAccess: roleContainer{Roles: []string{"nix-user", "nix-user"}},
		ResourceAccess: map[string]roleContainer{
			"api": {Roles: []string{"nix-user"}},
		},
	}

	identity := claims.toIdentity("api")

	if len(identity.Roles) != 1 {
		t.Errorf("expected deduplicated roles, got %v", identity.Roles)
	}
}

func TestToIdentity_UnknownClientIDYieldsRealmRolesOnly(t *testing.T) {
	claims := accessTokenClaims{
		RealmAccess: roleContainer{Roles: []string{"nix-user"}},
		ResourceAccess: map[string]roleContainer{
			"some-other-client": {Roles: []string{"nix-admin"}},
		},
	}

	identity := claims.toIdentity("nix-platform-api")

	if !reflect.DeepEqual(identity.Roles, []string{"nix-user"}) {
		t.Errorf("Roles = %v, want [nix-user]", identity.Roles)
	}
}
