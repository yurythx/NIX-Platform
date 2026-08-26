// Arquivo dto.go — formato público (JSON) do MVP de monitoramento real
// do Diário Oficial (MonitoredTerm/MatchedPublication), separado do
// domain.* pelo mesmo motivo que todo outro módulo desta plataforma
// separa: o formato de resposta é um contrato com o frontend, o domain é
// livre pra mudar de forma (ex.: acrescentar um campo interno) sem
// quebrar ninguém do lado de fora.
package transport

import (
	"time"

	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/application"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
)

type monitoredTermResponse struct {
	ID            string     `json:"id"`
	Label         string     `json:"label"`
	OABNumber     string     `json:"oab_number,omitempty"`
	OABState      string     `json:"oab_uf,omitempty"`
	ProcessNumber string     `json:"process_number,omitempty"`
	FreeText      string     `json:"free_text,omitempty"`
	Active        bool       `json:"active"`
	LastSyncedAt  *time.Time `json:"last_synced_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

func toMonitoredTermResponse(t domain.MonitoredTerm) monitoredTermResponse {
	return monitoredTermResponse{
		ID:            t.ID.String(),
		Label:         t.Label,
		OABNumber:     t.OABNumber,
		OABState:      t.OABState,
		ProcessNumber: t.ProcessNumber,
		FreeText:      t.FreeText,
		Active:        t.Active,
		LastSyncedAt:  t.LastSyncedAt,
		CreatedAt:     t.CreatedAt,
	}
}

func toMonitoredTermResponses(terms []domain.MonitoredTerm) []monitoredTermResponse {
	out := make([]monitoredTermResponse, 0, len(terms))
	for _, t := range terms {
		out = append(out, toMonitoredTermResponse(t))
	}
	return out
}

// matchedPublicationResponse é o formato público de
// domain.MatchedPublication — Texto é incluído por completo (ao
// contrário de scan_findings.Description, uma publicação judicial não
// tem uma versão "curta" natural que faça sentido truncar; quem consome
// decide se corta na exibição).
type matchedPublicationResponse struct {
	ID                  string    `json:"id"`
	Tribunal            string    `json:"tribunal"`
	Orgao               string    `json:"orgao"`
	TipoComunicacao     string    `json:"tipo_comunicacao"`
	Texto               string    `json:"texto"`
	ProcessNumber       string    `json:"process_number"`
	ProcessNumberMasked string    `json:"process_number_masked"`
	AvailabilityDate    time.Time `json:"availability_date"`
	Link                string    `json:"link,omitempty"`
	MonitoredTermID     string    `json:"monitored_term_id"`
	MonitoredTermLabel  string    `json:"monitored_term_label"`
	MatchedAt           time.Time `json:"matched_at"`
}

func toMatchedPublicationResponse(mp domain.MatchedPublication) matchedPublicationResponse {
	return matchedPublicationResponse{
		ID:                  mp.ID.String(),
		Tribunal:            mp.Tribunal,
		Orgao:               mp.Orgao,
		TipoComunicacao:     mp.TipoComunicacao,
		Texto:               mp.Texto,
		ProcessNumber:       mp.ProcessNumber,
		ProcessNumberMasked: mp.ProcessNumberMasked,
		AvailabilityDate:    mp.AvailabilityDate,
		Link:                mp.Link,
		MonitoredTermID:     mp.MonitoredTermID.String(),
		MonitoredTermLabel:  mp.MonitoredTermLabel,
		MatchedAt:           mp.MatchedAt,
	}
}

func toMatchedPublicationResponses(items []domain.MatchedPublication) []matchedPublicationResponse {
	out := make([]matchedPublicationResponse, 0, len(items))
	for _, mp := range items {
		out = append(out, toMatchedPublicationResponse(mp))
	}
	return out
}

// sourceHealthResponse é o formato público de application.SourceHealth —
// mesmo shape que scanning's ScannerHealthResponse (scanner/healthy/
// message/checked_at), só com "source" no lugar de "scanner": as duas
// telas ("saúde antes de escanear" e "saúde da fonte de dados do Diário
// Oficial") resolvem o mesmo problema, então usam o mesmo vocabulário.
type sourceHealthResponse struct {
	Source    string    `json:"source"`
	Healthy   bool      `json:"healthy"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

func toSourceHealthResponse(h application.SourceHealth) sourceHealthResponse {
	return sourceHealthResponse{Source: h.Source, Healthy: h.Healthy, Message: h.Message, CheckedAt: h.CheckedAt}
}
