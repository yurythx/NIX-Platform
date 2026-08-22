package auth

// accessTokenClaims mirrors the subset of a Keycloak access token's claims
// the platform cares about. Keycloak puts realm-wide roles under
// "realm_access.roles" and per-client roles under
// "resource_access.<client_id>.roles" — both are merged into Identity.Roles.
type accessTokenClaims struct {
	Subject           string                   `json:"sub"`
	PreferredUsername string                   `json:"preferred_username"`
	Email             string                   `json:"email"`
	RealmAccess       roleContainer            `json:"realm_access"`
	ResourceAccess    map[string]roleContainer `json:"resource_access"`
}

type roleContainer struct {
	Roles []string `json:"roles"`
}

// toIdentity merges realm roles with the roles granted for clientID into a
// single de-duplicated Identity.
func (c accessTokenClaims) toIdentity(clientID string) Identity {
	seen := make(map[string]struct{}, len(c.RealmAccess.Roles))
	roles := make([]string, 0, len(c.RealmAccess.Roles))

	add := func(rs []string) {
		for _, r := range rs {
			if _, ok := seen[r]; ok {
				continue
			}
			seen[r] = struct{}{}
			roles = append(roles, r)
		}
	}

	add(c.RealmAccess.Roles)
	if clientRoles, ok := c.ResourceAccess[clientID]; ok {
		add(clientRoles.Roles)
	}

	return Identity{
		Subject:  c.Subject,
		Username: c.PreferredUsername,
		Email:    c.Email,
		Roles:    roles,
	}
}
