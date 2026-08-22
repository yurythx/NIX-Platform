package httputil

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
)

var (
	validateOnce sync.Once
	validate     *validator.Validate
)

func getValidator() *validator.Validate {
	validateOnce.Do(func() {
		validate = validator.New(validator.WithRequiredStructEnabled())
	})
	return validate
}

// Validate runs struct-tag validation on dst (see go-playground/validator
// docs for tag syntax) and returns a client-safe *apperrors.Error
// summarizing every failed field, or nil if dst is valid.
func Validate(dst any) error {
	if err := getValidator().Struct(dst); err != nil {
		var validationErrs validator.ValidationErrors
		if errors.As(err, &validationErrs) {
			return apperrors.Validation(formatValidationErrors(validationErrs))
		}
		// Not a validation error (e.g. invalid struct passed) — treat as a
		// bad request rather than crashing the handler.
		return apperrors.BadRequest("invalid request payload")
	}
	return nil
}

func formatValidationErrors(errs validator.ValidationErrors) string {
	msgs := make([]string, 0, len(errs))
	for _, fe := range errs {
		msgs = append(msgs, fmt.Sprintf("%s: failed on %q", fe.Field(), fe.Tag()))
	}
	return strings.Join(msgs, "; ")
}
