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

// getValidator constrói o *validator.Validate uma única vez (é seguro para
// uso concorrente depois de construído, e a construção não é gratuita) e
// reutiliza a mesma instância em todo o processo.
func getValidator() *validator.Validate {
	validateOnce.Do(func() {
		validate = validator.New(validator.WithRequiredStructEnabled())
	})
	return validate
}

// Validate roda a validação por struct-tag em dst (ver a documentação do
// go-playground/validator para a sintaxe das tags, ex.: `validate:"required,email"`)
// e retorna um *apperrors.Error seguro de mostrar ao cliente, resumindo
// todo campo que falhou, ou nil se dst for válido (§45).
func Validate(dst any) error {
	if err := getValidator().Struct(dst); err != nil {
		var validationErrs validator.ValidationErrors
		if errors.As(err, &validationErrs) {
			return apperrors.Validation(formatValidationErrors(validationErrs))
		}
		// Não é um erro de validação (ex.: foi passada uma struct
		// inválida para o validador) — trata como bad request em vez de
		// derrubar o handler com um panic.
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
