package httputil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
)

// MaxRequestBodyBytes limita quanto de um corpo de requisição o DecodeJSON
// vai ler, defendendo a API contra payloads gigantes (§57).
const MaxRequestBodyBytes = 1 << 20 // 1 MiB

// DecodeJSON decodifica um corpo de requisição JSON em dst, rejeitando
// campos desconhecidos e corpos maiores que MaxRequestBodyBytes. Retorna
// um *apperrors.Error seguro de mostrar ao cliente em qualquer falha de
// decodificação.
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

	// Rejeita lixo sobrando depois do valor JSON — ex.: dois objetos JSON
	// concatenados no mesmo corpo.
	if dec.More() {
		return apperrors.BadRequest("request body must contain a single JSON object")
	}

	return nil
}
