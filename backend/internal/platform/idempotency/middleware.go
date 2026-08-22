package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/logging"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

// Header é o nome do cabeçalho HTTP que ativa a idempotência para uma
// requisição. Segue a convenção popularizada pela Stripe API.
const Header = "Idempotency-Key"

// MaxCachedResponseBytes limita quanto de uma resposta é guardado para
// replay. Toda resposta hoje gerada pelos endpoints que usam este
// middleware é um envelope JSON pequeno ({job_id, status}), então este
// teto é generoso; se um handler futuro devolver algo maior, a chave
// ainda funciona (o cliente recebe a resposta normalmente), só não fica
// disponível para replay — Complete não é chamado, a chave é liberada via
// Fail para permitir nova tentativa, e o ocorrido é logado.
const MaxCachedResponseBytes = 64 * 1024

// Middleware intercepta requisições que carregam o header Idempotency-Key
// e garante que a mesma chave nunca executa o handler seguinte mais de
// uma vez com sucesso: a primeira chamada processa normalmente e tem sua
// resposta guardada; chamadas repetidas com a mesma chave recebem de
// volta a resposta guardada (replay) em vez de reexecutar o caso de uso.
// Requisições sem o header passam direto, sem custo algum.
//
// Precisa rodar DEPOIS de auth.RequireAuthentication — a chave é escopada
// por usuário autenticado (identity.Subject + valor do header), para que
// dois usuários diferentes não corram risco de colidir ao escolherem,
// por coincidência, o mesmo valor de chave.
func Middleware(store Store, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawKey := r.Header.Get(Header)
			if rawKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			identity, ok := auth.IdentityFromContext(r.Context())
			if !ok || identity.Subject == "" {
				// Não deveria acontecer em produção — este middleware é
				// montado atrás de auth.RequireAuthentication — mas
				// nunca aplique idempotência sem conseguir escopar por
				// usuário; degrada para passar direto em vez de arriscar
				// colisão entre chamadores diferentes.
				next.ServeHTTP(w, r)
				return
			}
			key := identity.Subject + ":" + rawKey

			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxRequestBodyBytes))
			if err != nil {
				httputil.WriteError(w, r, logger, apperrors.BadRequest("request body too large or unreadable"))
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			requestHash := hashRequest(r.Method, r.URL.Path, body)

			existing, claimed, err := store.Claim(r.Context(), key, requestHash)
			if err != nil {
				logging.FromContext(r.Context(), logger).Error("idempotency: claim failed, allowing request through",
					slog.String("idempotency_key", rawKey), slog.Any("error", err))
				// Fail-open, no mesmo espírito do RateLimit middleware
				// (§ rate limiting distribuído): uma instabilidade no
				// Postgres não deve virar uma indisponibilidade total do
				// endpoint que a idempotência protege.
				next.ServeHTTP(w, r)
				return
			}

			if !claimed {
				handleExisting(w, r, logger, existing, requestHash)
				return
			}

			rec := &responseRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			finalizeClaim(r.Context(), store, logger, key, rec)
			metrics.IdempotencyOutcomesTotal.WithLabelValues("new").Inc()
		})
	}
}

// handleExisting decide o que responder quando esta chamada NÃO ganhou o
// direito de processar: reproduz a resposta guardada se a chave já
// concluiu com sucesso, recusa como reuso indevido se o payload não bate
// com o que gerou o registro existente, ou informa que a requisição
// original ainda está em andamento.
func handleExisting(w http.ResponseWriter, r *http.Request, logger *slog.Logger, existing *Record, requestHash string) {
	if existing.RequestHash != requestHash {
		metrics.IdempotencyOutcomesTotal.WithLabelValues("reused_key").Inc()
		httputil.WriteError(w, r, logger, apperrors.Conflict(
			"Idempotency-Key was already used with a different request",
		).WithCode("IDEMPOTENCY_KEY_REUSED"))
		return
	}

	if existing.Status == StatusCompleted {
		metrics.IdempotencyOutcomesTotal.WithLabelValues("replayed").Inc()
		if existing.ContentType != "" {
			w.Header().Set("Content-Type", existing.ContentType)
		}
		w.Header().Set("Idempotent-Replay", "true")
		w.WriteHeader(existing.ResponseStatus)
		_, _ = w.Write(existing.ResponseBody)
		return
	}

	// StatusProcessing (ou, numa janela de corrida muito estreita,
	// StatusFailed — ver o comentário de PostgresStore.Claim) — a
	// requisição original ainda não terminou.
	metrics.IdempotencyOutcomesTotal.WithLabelValues("conflict").Inc()
	httputil.WriteError(w, r, logger, apperrors.Conflict(
		"a request with this Idempotency-Key is already being processed",
	).WithCode("IDEMPOTENCY_KEY_IN_PROGRESS"))
}

// finalizeClaim persiste o resultado da requisição que esta chamada
// processou de fato: completa a chave (disponível para replay) se o
// handler respondeu com sucesso ou um erro de cliente (< 500), ou a
// libera (Fail, permitindo nova tentativa completa) se respondeu com um
// erro de servidor — um 500 não deve ser "lembrado" para sempre, o
// cliente pode tentar de novo esperando um resultado diferente.
func finalizeClaim(ctx context.Context, store Store, logger *slog.Logger, key string, rec *responseRecorder) {
	if rec.status >= http.StatusInternalServerError {
		if err := store.Fail(ctx, key); err != nil {
			logger.Error("idempotency: failed to release key after server error", slog.Any("error", err))
		}
		return
	}

	if rec.body.Len() > MaxCachedResponseBytes {
		logger.Warn("idempotency: response too large to cache, releasing key", slog.Int("size", rec.body.Len()))
		if err := store.Fail(ctx, key); err != nil {
			logger.Error("idempotency: failed to release oversized key", slog.Any("error", err))
		}
		return
	}

	if err := store.Complete(ctx, key, rec.status, rec.body.Bytes(), rec.Header().Get("Content-Type")); err != nil {
		logger.Error("idempotency: failed to persist response for replay", slog.Any("error", err))
	}
}

// hashRequest identifica de forma estável "qual requisição" uma chave de
// idempotência foi usada para — método, caminho e corpo. Não inclui
// headers (o Authorization muda a cada renovação de token sem representar
// uma requisição logicamente diferente) nem query string (nenhum endpoint
// protegido por este middleware hoje usa parâmetros de query).
func hashRequest(method, path string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{'\n'})
	h.Write([]byte(path))
	h.Write([]byte{'\n'})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// responseRecorder envolve o http.ResponseWriter real para capturar o
// status e o corpo da resposta enquanto a repassa ao cliente em tempo
// real (a escrita em Write() vai para os dois lugares) — necessário para
// que finalizeClaim saiba o que guardar para um replay futuro sem atrasar
// a resposta desta primeira chamada.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	body        bytes.Buffer
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	// Guarda mesmo além de MaxCachedResponseBytes — finalizeClaim decide
	// se cabe no cache; cortar aqui perderia a chance de repassar a
	// resposta completa e correta ao cliente desta primeira chamada.
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}
