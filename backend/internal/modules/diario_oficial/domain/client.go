// Package domain guarda o contrato do módulo diario_oficial com o sistema
// externo do Diário Oficial. A implementação HTTP real fica em
// infrastructure/ — este pacote não sabe nada sobre HTTP, RabbitMQ ou
// PostgreSQL.
package domain

import (
	"context"
	"time"
)

// CheckResult é o resultado de uma verificação bem-sucedida no Diário
// Oficial.
type CheckResult struct {
	StatusCode int
	Summary    string
}

// SearchQuery é um critério de busca contra o sistema externo do Diário
// Oficial — espelha (não copia 1:1: só os campos que este módulo usa) os
// parâmetros de busca reais que o DJEN (Diário de Justiça Eletrônico
// Nacional, comunicaapi.pje.jus.br) aceita. Pelo menos um critério
// (OAB+UF, ProcessNumber ou FreeText) precisa estar preenchido — a mesma
// regra que MonitoredTerm.Validate já impõe na origem, então um Client
// nunca recebe uma SearchQuery vazia.
type SearchQuery struct {
	OABNumber     string
	OABState      string
	ProcessNumber string
	FreeText      string
	// Since limita a busca a publicações disponibilizadas a partir desta
	// data (inclusive) — nil busca sem limite inferior. Usado pelo
	// worker pra buscar só o que é NOVO desde o último ciclo (ver
	// application.syncSinceDate), nunca o histórico inteiro a cada tick.
	Since *time.Time
	// Page/PageSize: 1-indexado, espelhando a paginação do DJEN
	// (`pagina`/`itensPorPagina`) — não a mesma Params de
	// internal/domain/pagination (aquela é pro CONTRATO HTTP desta
	// plataforma com seu próprio frontend; esta é pro contrato deste
	// Client com um sistema externo, sem relação uma com a outra).
	Page     int
	PageSize int
}

// SearchResultItem é uma publicação individual devolvida por uma busca —
// já traduzida do formato do provedor externo (JSON do DJEN) pro
// vocabulário desta plataforma, mesmo raciocínio de domain.Finding no
// módulo scanning: nenhum outro pacote além do Client concreto (ver
// infrastructure.HTTPClient) sabe o formato bruto do provedor.
type SearchResultItem struct {
	// ExternalID é o id que o próprio provedor atribui à comunicação —
	// a chave de deduplicação entre ciclos de sync sucessivos (ver
	// migration 000026, UNIQUE(external_id)).
	ExternalID          int64
	Tribunal            string
	Orgao               string
	TipoComunicacao     string
	Texto               string
	ProcessNumber       string
	ProcessNumberMasked string
	AvailabilityDate    time.Time
	Link                string
	// RawPayload é o JSON bruto do item, exatamente como o provedor
	// devolveu — guardado sem perda (ver migration 000026's comentário em
	// raw_payload) mesmo que este Go struct só extraia um subconjunto de
	// campos.
	RawPayload []byte
}

// SearchResult é a página de resultados de uma busca.
type SearchResult struct {
	Items      []SearchResultItem
	TotalCount int
}

// Client abstrai o sistema externo do Diário Oficial, para que a lógica de
// aplicação do módulo seja testável sem depender de um endpoint real —
// nos testes, uma implementação falsa (fake) desta interface substitui a
// chamada HTTP de verdade.
type Client interface {
	Check(ctx context.Context) (*CheckResult, error)
	// Search executa uma busca de publicações contra o provedor externo
	// configurado — o coração do monitoramento (ver
	// application.syncTerm): Check só confirma que o provedor está de
	// pé, Search é o que de fato traz o conteúdo novo pra casar contra
	// MonitoredTerm.
	Search(ctx context.Context, query SearchQuery) (*SearchResult, error)
}
