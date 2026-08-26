package main

import "testing"

func TestGeneratePassword_IsNonEmptyAndVariesAcrossCalls(t *testing.T) {
	a, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword: %v", err)
	}
	if len(a) < 20 {
		t.Errorf("password length = %d, want >= 20 (passwordBytes=%d base64-encoded)", len(a), passwordBytes)
	}

	b, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword (segunda chamada): %v", err)
	}
	if a == b {
		t.Error("duas chamadas geraram a mesma senha — gerador não está de fato aleatório")
	}
}

func TestSplitRoles(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"nix-admin,nix-user", []string{"nix-admin", "nix-user"}},
		{"nix-admin, nix-user", []string{"nix-admin", "nix-user"}},
		{"nix-admin,,nix-user", []string{"nix-admin", "nix-user"}},
		{"", []string{}},
		{"  ", []string{}},
	}
	for _, tc := range cases {
		got := splitRoles(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitRoles(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitRoles(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}
