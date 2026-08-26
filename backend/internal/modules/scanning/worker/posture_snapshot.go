package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/yurythx/nix-platform/internal/modules/scanning/application"
)

// snapshotInterval: uma vez por dia já é o suficiente pra um gráfico de
// tendência (ninguém precisa ver a postura de segurança mudar de hora em
// hora) — mesma ordem de grandeza de internal/platform/idempotency.Cleanup
// (15min) e ratelimit.Cleanup (5min), só que bem mais espaçado porque o
// dado em si (achados abertos entre todo projeto) muda devagar.
const snapshotInterval = 24 * time.Hour

// PostureSnapshotLoop grava periodicamente o resumo agregado do dia em
// scanning_posture_snapshots (ver application.Service.SnapshotSecurityPosture)
// — registrado como um processor do worker (mesmo padrão de
// ratelimit.Cleanup/idempotency.Cleanup, ver internal/app/worker.go).
//
// Diferente do padrão usual de "espera o primeiro tick antes de fazer
// qualquer coisa" (idempotency.Cleanup/ratelimit.Cleanup): aqui o
// primeiro snapshot roda IMEDIATAMENTE, antes de entrar no loop — com um
// intervalo de 24h, esperar o primeiro tick significaria a série
// temporal só ganhar seu primeiro ponto um dia inteiro depois do worker
// subir, o que atrasaria por nada a utilidade do gráfico de tendência
// pra quem acabou de habilitar isto.
func PostureSnapshotLoop(svc *application.Service, logger *slog.Logger) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		snapshotOnce(ctx, svc, logger)

		ticker := time.NewTicker(snapshotInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				snapshotOnce(ctx, svc, logger)
			}
		}
	}
}

// snapshotOnce grava um snapshot e loga (sem retornar erro pro
// chamador): uma falha isolada — um soluço de conexão com o Postgres no
// meio de um tick, por exemplo — não deveria derrubar/reiniciar o loop
// inteiro (supervised, em internal/app/worker.go, reiniciaria com
// backoff se este processor retornasse erro; um erro por tick é
// autolimitado o bastante pra não precisar disso — o próximo tick, 24h
// depois, tenta de novo sozinho).
func snapshotOnce(ctx context.Context, svc *application.Service, logger *slog.Logger) {
	if err := svc.SnapshotSecurityPosture(ctx); err != nil {
		logger.Error("scanning: failed to snapshot security posture (best-effort, will retry on the next tick)", slog.Any("error", err))
	}
}
