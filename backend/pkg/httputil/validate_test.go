package httputil

import "testing"

type validatedDTO struct {
	Name  string `validate:"required"`
	Email string `validate:"required,email"`
}

func TestValidate_Success(t *testing.T) {
	dto := validatedDTO{Name: "nix", Email: "nix@example.com"}
	if err := Validate(dto); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingRequiredField(t *testing.T) {
	dto := validatedDTO{Email: "nix@example.com"}
	if err := Validate(dto); err == nil {
		t.Fatal("expected an error for a missing required field")
	}
}

func TestValidate_InvalidEmail(t *testing.T) {
	dto := validatedDTO{Name: "nix", Email: "not-an-email"}
	if err := Validate(dto); err == nil {
		t.Fatal("expected an error for an invalid email")
	}
}
