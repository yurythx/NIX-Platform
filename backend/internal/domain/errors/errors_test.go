package errors

import (
	stderrors "errors"
	"testing"
)

func TestConstructors_StatusAndCode(t *testing.T) {
	cases := []struct {
		name       string
		err        *Error
		wantStatus int
		wantCode   Code
	}{
		{"BadRequest", BadRequest("bad"), 400, CodeBadRequest},
		{"Unauthorized", Unauthorized("no"), 401, CodeUnauthorized},
		{"Forbidden", Forbidden("nope"), 403, CodeForbidden},
		{"NotFound", NotFound("missing"), 404, CodeNotFound},
		{"Conflict", Conflict("dup"), 409, CodeConflict},
		{"Validation", Validation("invalid"), 422, CodeValidation},
		{"RateLimited", RateLimited("slow down"), 429, CodeRateLimited},
		{"DependencyUnavailable", DependencyUnavailable("down"), 503, CodeDependencyUnavailable},
		{"Internal", Internal(stderrors.New("boom")), 500, CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Status != tc.wantStatus {
				t.Errorf("Status = %d, want %d", tc.err.Status, tc.wantStatus)
			}
			if tc.err.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", tc.err.Code, tc.wantCode)
			}
		})
	}
}

func TestInternal_DoesNotExposeCause(t *testing.T) {
	cause := stderrors.New("password=hunter2 leaked")
	err := Internal(cause)
	if err.Message == cause.Error() {
		t.Fatal("Internal() must not surface the wrapped cause in the client-facing message")
	}
}

func TestWithCode_OverridesCodeKeepsStatus(t *testing.T) {
	base := DependencyUnavailable("integration down")
	custom := base.WithCode("INTEGRATION_UNAVAILABLE")

	if custom.Status != base.Status {
		t.Errorf("Status changed: got %d, want %d", custom.Status, base.Status)
	}
	if custom.Code != "INTEGRATION_UNAVAILABLE" {
		t.Errorf("Code = %q, want INTEGRATION_UNAVAILABLE", custom.Code)
	}
	if base.Code != CodeDependencyUnavailable {
		t.Error("WithCode must not mutate the receiver")
	}
}

func TestAs_UnwrapsWrappedAppError(t *testing.T) {
	appErr := NotFound("job not found")
	wrapped := fmtErrorf(appErr)

	got, ok := As(wrapped)
	if !ok {
		t.Fatal("expected As to find the wrapped *Error")
	}
	if got.Code != CodeNotFound {
		t.Errorf("Code = %q, want %q", got.Code, CodeNotFound)
	}
}

func fmtErrorf(err error) error {
	return stderrors.Join(err)
}
