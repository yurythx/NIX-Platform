package domain

import (
	"context"
	"time"
)

// PostureSnapshot é o resumo agregado de achados abertos de UM DIA —
// a série temporal que responde "estamos melhorando ou piorando?", uma
// pergunta que application.Service.SecurityPosture sozinho nunca
// respondia (só mostra o AGORA). Mesmos campos que SecurityPosture
// (application/posture.go) já tem, capturados num ponto no tempo — Date
// é só a data (sem hora), já que só existe UM snapshot "oficial" por
// dia (ver migration 000025, PRIMARY KEY em snapshot_date).
type PostureSnapshot struct {
	Date            time.Time
	OpenCritical    int
	OpenHigh        int
	OpenMedium      int
	OpenLow         int
	TriagedCount    int
	ProjectsScanned int
}

// PostureRepository persiste e consulta a série temporal de
// PostureSnapshot. Interface própria, mesmo raciocínio de
// TriageRepository (ver seu comentário) — um conceito novo e pequeno,
// que não deveria inflar domain.Repository nem obrigar cada fake de
// teste dela a ganhar métodos que não usa.
type PostureRepository interface {
	// SaveSnapshot grava (ou substitui, se já existia um snapshot pra
	// esta mesma data) o resumo do dia — chamado periodicamente pelo
	// worker (ver internal/modules/scanning/worker's
	// PostureSnapshotLoop), nunca por uma requisição HTTP direta.
	// Rodar mais de uma vez no mesmo dia é seguro: a execução mais
	// recente simplesmente sobrescreve a de mais cedo, nunca acumula
	// duas linhas pro mesmo dia.
	SaveSnapshot(ctx context.Context, s PostureSnapshot) error

	// ListSnapshots retorna os últimos `days` dias de snapshot, data
	// mais ANTIGA primeiro (a ordem que um gráfico de linha do tempo
	// espera) — dias sem snapshot nenhum (worker não rodou ainda
	// naquele dia, ou ainda não existia) simplesmente não aparecem na
	// lista, nunca uma linha "zerada" fingindo que existiu.
	ListSnapshots(ctx context.Context, days int) ([]PostureSnapshot, error)
}
