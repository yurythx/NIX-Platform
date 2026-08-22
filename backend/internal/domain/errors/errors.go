// Package errors defines the application-wide error taxonomy. Domain and
// application code returns these errors instead of raw driver/library
// errors; the transport layer maps them to HTTP status codes and never
// leaks internal details (stack traces, SQL, driver messages) to clients.
package errors

import (
	stderrors "errors"
	"fmt"
)

// Code is a stable, machine-readable error identifier returned to clients
// in the standard error envelope's "code" field.
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
	CodeInternal              Code = "INTERNAL_ERROR"
)

// Error is the canonical application error. Message is safe to expose to
// API clients; Err (when set) wraps the underlying cause for logging only.
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

// Unwrap allows errors.Is/errors.As to reach the wrapped cause.
func (e *Error) Unwrap() error { return e.Err }

// WithCode returns a copy of e with its Code replaced. Useful for
// domain-specific codes that still map to a standard HTTP status, e.g.
// DependencyUnavailable("...").WithCode("INTEGRATION_UNAVAILABLE").
func (e *Error) WithCode(code Code) *Error {
	cp := *e
	cp.Code = code
	return &cp
}

// WithCause returns a copy of e wrapping the given underlying error for
// logging/observability, without changing the message exposed to clients.
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

// Internal wraps an unexpected error. The message returned to clients is
// always generic; callers must not put sensitive detail in it.
func Internal(cause error) *Error {
	return &Error{Status: 500, Code: CodeInternal, Message: "an unexpected error occurred", Err: cause}
}

// As is a small helper for transport code: it reports whether err (or
// something it wraps) is an *Error, returning it if so.
func As(err error) (*Error, bool) {
	var appErr *Error
	if stderrors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}
