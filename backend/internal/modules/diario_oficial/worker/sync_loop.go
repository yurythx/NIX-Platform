package worker

import (
	"context"
	"time"

	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/application"
)

// syncInterval: o DJEN atualiza durante o horário forense (dias úteis),
// então checar a cada 6h cobre isso sem martelar o provedor externo fora
// de propósito — mais espaçado que ratelimit.Cleanup (5min)/
// idempotency.Cleanup (15min), mais frequente que
// scanning.worker.snapshotInterval (24h): um prazo processual pode ser
// contado em dias corridos, então "descobrir a publicação só amanhã de
// manhã" já seria tarde demais pra alguns casos.
const syncInterval = 6 * time.Hour

// DiarioOficialSyncLoop sincroniza periodicamente todo termo monitorado
// ativo contra o DJEN (ver application.Service.SyncAll) — registrado como
// um processor do worker (mesmo padrão de scanning.worker.
// PostureSnapshotLoop, ver internal/app/worker.go).
//
// Mesmo raciocínio de PostureSnapshotLoop: o primeiro sync roda
// IMEDIATAMENTE, antes de entrar no loop — esperar o primeiro tick (6h)
// atrasaria por nada a utilidade de um termo recém-cadastrado.
func DiarioOficialSyncLoop(svc *application.Service) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		svc.SyncAll(ctx)

		ticker := time.NewTicker(syncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				svc.SyncAll(ctx)
			}
		}
	}
}
