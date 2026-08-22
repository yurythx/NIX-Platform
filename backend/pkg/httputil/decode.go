package httputil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
)

// MaxRequestBodyBytes bounds how much of a request body DecodeJSON will
// read, defending the API against oversized payloads (§57).
const MaxRequestBodyBytes = 1 << 20 // 1 MiB

// DecodeJSON decodes a JSON request body into dst, rejecting unknown
// fields and bodies over MaxRequestBodyBytes. It returns a client-safe
// *apperrors.Error on any decoding failure.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return apperrors.BadRequest("request body too large")
		}
		if errors.Is(err, io.EOF) {
			return apperrors.BadRequest("request body must not be empty")
		}
		return apperrors.BadRequest(fmt.Sprintf("invalid request body: %v", err))
	}

	// Reject trailing garbage after the JSON value.
	if dec.More() {
		return apperrors.BadRequest("request body must contain a single JSON object")
	}

	return nil
}
