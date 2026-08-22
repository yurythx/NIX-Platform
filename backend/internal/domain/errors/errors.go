// Package errors define a taxonomia de erros usada em toda a aplicação.
// Código de domínio e de aplicação retorna estes erros em vez de erros
// brutos de driver/biblioteca; a camada de transporte os mapeia para
// códigos de status HTTP e nunca vaza detalhe interno (stack trace, SQL,
// mensagens de driver) para o cliente.
package errors

import (
	stderrors "errors"
	"fmt"
)

// Code é um identificador de erro estável e legível por máquina, retornado
// ao cliente no campo "code" do envelope de erro padrão.
type Code string

const (
	CodeBadRequest            Code = "BAD_REQUEST"
	CodeUnauthorized          Code = "UNAUTHORIZED"
	CodeForbidden             Code = "FORBIDDEN"
	CodeNotFound              Code = "NOT_FOUND"
	CodeConflict              Code = "CONFLICT"
	CodeValidation            Code = "VALIDATION_ERROR"
	CodeRateLimited           Code = "RATE_LIMITED"
	CodeDependencyUnavailable Code = "DEPENDENCY_UNAVAILABLE"
	CodeFeatureDisabled       Code = "FEATURE_DISABLED"
	CodeInternal              Code = "INTERNAL_ERROR"
)

// Error é o erro canônico da aplicação. Message é seguro de expor a
// clientes da API; Err (quando definido) envolve a causa subjacente
// apenas para fins de log — nunca é serializado na resposta HTTP.
type Error struct {
	Status  int
	Code    Code
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap permite que errors.Is/errors.As alcancem a causa envolvida.
func (e *Error) Unwrap() error { return e.Err }

// WithCode retorna uma cópia de e com o Code substituído. Útil para
// códigos específicos de domínio que ainda assim mapeiam para um status
// HTTP padrão, ex.:
// DependencyUnavailable("...").WithCode("INTEGRATION_UNAVAILABLE").
func (e *Error) WithCode(code Code) *Error {
	cp := *e
	cp.Code = code
	return &cp
}

// WithCause retorna uma cópia de e envolvendo o erro subjacente informado,
// só para fins de log/observabilidade, sem alterar a mensagem exposta ao
// cliente.
func (e *Error) WithCause(cause error) *Error {
	cp := *e
	cp.Err = cause
	return &cp
}

func BadRequest(message string) *Error {
	return &Error{Status: 400, Code: CodeBadRequest, Message: message}
}

func Unauthorized(message string) *Error {
	return &Error{Status: 401, Code: CodeUnauthorized, Message: message}
}

func Forbidden(message string) *Error {
	return &Error{Status: 403, Code: CodeForbidden, Message: message}
}

func NotFound(message string) *Error {
	return &Error{Status: 404, Code: CodeNotFound, Message: message}
}

func Conflict(message string) *Error {
	return &Error{Status: 409, Code: CodeConflict, Message: message}
}

func Validation(message string) *Error {
	return &Error{Status: 422, Code: CodeValidation, Message: message}
}

func RateLimited(message string) *Error {
	return &Error{Status: 429, Code: CodeRateLimited, Message: message}
}

func DependencyUnavailable(message string) *Error {
	return &Error{Status: 503, Code: CodeDependencyUnavailable, Message: message}
}

// FeatureDisabled reporta que uma funcionalidade existe mas foi desligada
// via feature flag (internal/platform/configflags) — status 503, como
// DependencyUnavailable, já que do ponto de vista do cliente é a mesma
// experiência ("isto não está disponível agora"), mas com um Code
// específico para o cliente distinguir "provedor externo com problema" de
// "um administrador desligou isto de propósito".
func FeatureDisabled(message string) *Error {
	return &Error{Status: 503, Code: CodeFeatureDisabled, Message: message}
}

// Internal envolve um erro inesperado. A mensagem retornada ao cliente é
// sempre genérica; quem chama não deve colocar detalhe sensível nela — o
// detalhe real fica só em cause, disponível para o log.
func Internal(cause error) *Error {
	return &Error{Status: 500, Code: CodeInternal, Message: "an unexpected error occurred", Err: cause}
}

// As é um pequeno helper para código de transporte: reporta se err (ou
// algo que ele envolve) é um *Error, retornando-o se for o caso.
func As(err error) (*Error, bool) {
	var appErr *Error
	if stderrors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}
