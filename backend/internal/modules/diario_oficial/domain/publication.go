package domain

import (
	"time"

	"github.com/google/uuid"
)

// Publication é uma comunicação/publicação já lida do Diário Oficial e
// persistida — nunca buscada sob demanda pra responder uma consulta do
// usuário (ver migration 000026); o worker (application.syncTerm) é o
// único lugar que fala com o Client, sempre gravando o resultado aqui
// antes de qualquer tela ler.
type Publication struct {
	ID                  uuid.UUID
	ExternalID          int64
	Tribunal            string
	Orgao               string
	TipoComunicacao     string
	Texto               string
	ProcessNumber       string
	ProcessNumberMasked string
	AvailabilityDate    time.Time
	Link                string
	RawPayload          []byte
	CreatedAt           time.Time
}

// PublicationMatch registra que uma Publication casou com um
// MonitoredTerm — n:n deliberado (ver migration 000026): a mesma
// publicação pode citar vários termos monitorados diferentes, e o mesmo
// termo casa com várias publicações ao longo do tempo.
type PublicationMatch struct {
	ID              uuid.UUID
	PublicationID   uuid.UUID
	MonitoredTermID uuid.UUID
	MatchedAt       time.Time
}

// MatchedPublication é uma Publication já unida com o contexto do
// casamento (MonitoredTermID/MatchedAt) — a forma que
// ListPublicationsForTerm/ListRecentMatches devolvem, pra quem consome
// não precisar de uma segunda consulta só pra saber QUANDO/COM QUAL
// termo cada publicação casou.
type MatchedPublication struct {
	Publication
	MonitoredTermID    uuid.UUID
	MonitoredTermLabel string
	MatchedAt          time.Time
}
