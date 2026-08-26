// Package infrastructure implementa as dependências externas do módulo
// diario_oficial: um cliente HTTP real contra o DJEN (Diário de Justiça
// Eletrônico Nacional, mantido pelo CNJ — comunicaapi.pje.jus.br), a API
// pública gratuita que boa parte do mercado de legaltech brasileiro
// (Jusbrasil, Escavador, Turivius, ...) usa como fonte real de
// publicações judiciais, em vez de raspar cada diário estadual
// individualmente.
package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
	"github.com/yurythx/nix-platform/internal/platform/resilience"
)

// providerLabel é o valor deste cliente para o rótulo "provider" em toda
// métrica nix_integration_* (§53).
const providerLabel = "diario-oficial"

// djenDateLayout é o formato de data que o DJEN aceita em
// dataDisponibilizacaoInicio/Fim e devolve em data_disponibilizacao —
// confirmado contra a API real (comunicaapi.pje.jus.br), não documentação
// de terceiro.
const djenDateLayout = "2006-01-02"

// defaultPageSize: nem tão pequeno que precise de muitas páginas pra um
// termo com bastante publicação nova, nem tão grande que uma resposta
// fique pesada demais — 50 é a mesma ordem de grandeza que
// application.maxSyncPagesPerTerm * defaultPageSize cobre num ciclo de
// sync sem estourar o timeout do HTTP client.
const defaultPageSize = 50

// HTTPClient chama o DJEN via HTTP. Nunca bloqueia por mais tempo que o
// timeout configurado (§48) e nunca entra em panic por um endpoint
// ausente/inalcançável — ambos os casos aparecem como um erro
// DependencyUnavailable seguro de mostrar ao cliente, em vez disso. A
// chamada de rede em si roda atrás de um circuit breaker (§ Circuit
// Breaker & Resiliência HTTP): depois de falhas consecutivas, o breaker
// abre e as chamadas passam a falhar rápido com CIRCUIT_OPEN, sem sequer
// tentar a requisição, até o DJEN mostrar sinal de vida de novo. Check e
// Search compartilham o MESMO breaker — as duas são a mesma dependência
// externa aos olhos da resiliência, mesmo que uma só confira status e a
// outra busque conteúdo.
type HTTPClient struct {
	baseURL string
	client  *http.Client
	breaker *resilience.Breaker[*http.Response]
}

// NewHTTPClient constrói um HTTPClient contra baseURL, com o timeout e o
// circuit breaker (logger recebe as transições de estado) configurados.
func NewHTTPClient(baseURL string, timeout time.Duration, logger *slog.Logger) *HTTPClient {
	return &HTTPClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
		breaker: resilience.New[*http.Response](resilience.Options{Name: providerLabel, Logger: logger}),
	}
}

var _ domain.Client = (*HTTPClient)(nil)

// do executa req atrás do circuit breaker, com as mesmas métricas
// nix_integration_* e a mesma tradução de erro pra apperrors.Error —
// compartilhado por Check e Search pra nunca divergirem em como um dos
// dois trata falha/timeout/circuito aberto.
func (c *HTTPClient) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	metrics.IntegrationRequestsTotal.WithLabelValues(providerLabel).Inc()
	start := time.Now()
	// O status >= 500 é verificado DENTRO do callback do breaker, não
	// depois — assim tanto uma falha de rede quanto um provedor
	// respondendo consistentemente com erro de servidor contam como
	// falha para o circuit breaker. Um 4xx (ex.: 404) não conta: é uma
	// resposta HTTP válida, só não a que se esperava, e não é sinal de
	// que o provedor está indisponível.
	resp, err := c.breaker.Execute(func() (*http.Response, error) {
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= http.StatusInternalServerError {
			resp.Body.Close()
			return nil, fmt.Errorf("diario oficial responded with status %d", resp.StatusCode)
		}
		return resp, nil
	})
	metrics.IntegrationDuration.WithLabelValues(providerLabel).Observe(time.Since(start).Seconds())
	if err != nil {
		metrics.IntegrationFailuresTotal.WithLabelValues(providerLabel).Inc()
		if appErr, ok := apperrors.As(err); ok && appErr.Code == "CIRCUIT_OPEN" {
			// Já é um erro de domínio pronto para o cliente — repassa
			// como está, sem envolver numa mensagem genérica de mais.
			return nil, appErr
		}
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("diario oficial request failed: %v", err)).WithCode("INTEGRATION_UNAVAILABLE")
	}
	return resp, nil
}

func (c *HTTPClient) Check(ctx context.Context) (*domain.CheckResult, error) {
	// Um ambiente sem DIARIO_OFICIAL_BASE_URL configurada deve reportar a
	// integração como indisponível de forma previsível, não tentar uma
	// requisição HTTP para uma URL vazia e falhar de um jeito confuso.
	if c.baseURL == "" {
		return nil, apperrors.DependencyUnavailable("Diário Oficial integration is not configured").WithCode("INTEGRATION_UNAVAILABLE")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("diario_oficial: build request: %w", err)
	}

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &domain.CheckResult{
		StatusCode: resp.StatusCode,
		Summary:    fmt.Sprintf("responded with HTTP %d", resp.StatusCode),
	}, nil
}

// djenResponse é o envelope que o DJEN devolve — confirmado contra a API
// real (comunicaapi.pje.jus.br/api/v1/comunicacao), não um formato
// documentado por terceiro. Items fica como json.RawMessage: guardamos o
// JSON bruto de cada item em domain.SearchResultItem.RawPayload sem
// perda nenhuma (ver migration 000026's comentário em raw_payload),
// mesmo decodificando só um subconjunto de campos pra djenItem abaixo.
type djenResponse struct {
	Status  string            `json:"status"`
	Message string            `json:"message"`
	Count   int               `json:"count"`
	Items   []json.RawMessage `json:"items"`
}

// djenItem é o subconjunto de campos de uma comunicação do DJEN que este
// módulo de fato usa — o payload real tem bem mais campos (destinatários,
// advogados, hash, status de cancelamento, ...), preservados em
// RawPayload pra quem precisar deles no futuro sem exigir uma segunda ida
// ao DJEN pra recuperá-los.
type djenItem struct {
	ID                       int64  `json:"id"`
	DataDisponibilizacao     string `json:"data_disponibilizacao"`
	SiglaTribunal            string `json:"siglaTribunal"`
	TipoComunicacao          string `json:"tipoComunicacao"`
	NomeOrgao                string `json:"nomeOrgao"`
	Texto                    string `json:"texto"`
	NumeroProcesso           string `json:"numero_processo"`
	Link                     string `json:"link"`
	NumeroProcessoComMascara string `json:"numeroprocessocommascara"`
}

// Search busca publicações no DJEN que casam com query — GET
// {baseURL}?numeroOab=...&ufOab=...&numeroProcesso=...&texto=...&
// dataDisponibilizacaoInicio=...&pagina=...&itensPorPagina=..., só com os
// parâmetros que query de fato preenche (um numeroOab vazio, por
// exemplo, busca TODO tribunal/processo — nunca mandado à toa).
func (c *HTTPClient) Search(ctx context.Context, query domain.SearchQuery) (*domain.SearchResult, error) {
	if c.baseURL == "" {
		return nil, apperrors.DependencyUnavailable("Diário Oficial integration is not configured").WithCode("INTEGRATION_UNAVAILABLE")
	}

	reqURL, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("diario_oficial: parse base url: %w", err)
	}
	q := reqURL.Query()
	if query.OABNumber != "" {
		q.Set("numeroOab", query.OABNumber)
	}
	if query.OABState != "" {
		q.Set("ufOab", query.OABState)
	}
	if query.ProcessNumber != "" {
		q.Set("numeroProcesso", query.ProcessNumber)
	}
	if query.FreeText != "" {
		q.Set("texto", query.FreeText)
	}
	if query.Since != nil {
		q.Set("dataDisponibilizacaoInicio", query.Since.Format(djenDateLayout))
	}
	page := query.Page
	if page < 1 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize < 1 {
		pageSize = defaultPageSize
	}
	q.Set("pagina", strconv.Itoa(page))
	q.Set("itensPorPagina", strconv.Itoa(pageSize))
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("diario_oficial: build search request: %w", err)
	}

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parsed djenResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("diario oficial: decode search response: %v", err)).WithCode("INTEGRATION_UNAVAILABLE")
	}

	items := make([]domain.SearchResultItem, 0, len(parsed.Items))
	for _, raw := range parsed.Items {
		var item djenItem
		if err := json.Unmarshal(raw, &item); err != nil {
			// Um item malformado isolado não deveria descartar a página
			// inteira — pula só ele, segue com o resto (mesmo raciocínio
			// de tolerância a dado ruim que scanning adota pra um scanner
			// individual falhando dentro de um scan com vários).
			continue
		}
		availabilityDate, err := time.Parse(djenDateLayout, item.DataDisponibilizacao)
		if err != nil {
			continue
		}
		items = append(items, domain.SearchResultItem{
			ExternalID:          item.ID,
			Tribunal:            item.SiglaTribunal,
			Orgao:               item.NomeOrgao,
			TipoComunicacao:     item.TipoComunicacao,
			Texto:               item.Texto,
			ProcessNumber:       item.NumeroProcesso,
			ProcessNumberMasked: item.NumeroProcessoComMascara,
			AvailabilityDate:    availabilityDate,
			Link:                item.Link,
			RawPayload:          append([]byte(nil), raw...),
		})
	}

	return &domain.SearchResult{Items: items, TotalCount: parsed.Count}, nil
}
