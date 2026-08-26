package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// sweepInterval: staleAfter é da ordem de dezenas de minutos (ver
// SweepStale), então checar a cada 5min já é bem mais granular do que
// precisa sem gastar uma consulta à toa — mesma ordem de grandeza de
// ratelimit.Cleanup/idempotency.Cleanup.
const sweepInterval = 5 * time.Minute

// StaleJobHandler dá o desfecho TERMINAL certo pra um job encontrado
// preso em "processing" — normalmente dead-lettering, com os MESMOS
// efeitos colaterais (evento de outbox, auditoria, notificação) que um
// dead-letter "normal" (esgotado pelo RabbitMQ) já tem, ver
// scanning.Service.HandleScanDeadLetter/diario_oficial.Service.
// HandleDeadLetter — os dois módulos que hoje usam o pipeline
// job→outbox→worker. reason descreve por que o sweeper decidiu que este
// job está órfão (nunca "max retries exceeded" — isto não passou pelo
// RabbitMQ retry nenhum, o worker que o processava simplesmente nunca
// voltou a se manifestar).
type StaleJobHandler func(ctx context.Context, jobID, correlationID uuid.UUID, reason string) error

// SweepStale é um processor de worker (mesmo padrão de
// ratelimit.Cleanup/idempotency.Cleanup — ver internal/app/worker.go)
// que recupera job ÓRFÃO: preso em "processing" há mais de staleAfter,
// nunca mais atualizado. Acontece quando o worker que o processava
// morre no meio do trabalho — crash, OOM, `docker compose restart`/
// `--force-recreate` no meio de um job, o host reiniciando — sem nunca
// chamar MarkCompleted/MarkFailed. Sem isto, esse job fica preso PRA
// SEMPRE: a mensagem do RabbitMQ que disparou o processamento já foi
// confirmada (ack) muito antes de o worker morrer, então nenhuma
// redelivery chega nunca, e a UI mostra "Rodando" indefinidamente — o
// achado real que levou a este arquivo existir (usuário viu um scan
// SonarQube preso em "0% Rodando" desde a noite anterior, sem nunca
// terminar).
//
// staleAfter precisa ficar ACIMA do maior timeout interno legítimo de
// qualquer scanner (hoje: SCANNING_ZAP_SCAN_TIMEOUT, 30min por padrão) —
// um job legitimamente ainda em andamento não deveria nunca ser varrido
// por engano. Se isso acontecer mesmo assim (staleAfter configurado
// baixo demais, ou um scan genuinamente mais lento que o esperado), o
// handler original — se algum dia voltar a se manifestar — tenta gravar
// num job que já virou "dead_letter"; CanTransition rejeita essa escrita
// (DeadLetter não tem transição de saída nenhuma) e o SELECT ... FOR
// UPDATE dentro de transition() serializa as duas tentativas, então
// nunca corrompe o dado — só perde silenciosamente o resultado tardio,
// o mesmo trade-off que todo sistema de fila com timeout de visibilidade
// (Sidekiq, Celery, ...) já aceita.
//
// handlers mapeia jobs.Type -> o StaleJobHandler daquele módulo. Um tipo
// sem handler registrado é logado e pulado, nunca derruba o sweep
// inteiro (nem os outros jobs órfãos do mesmo ciclo).
func SweepStale(pool *pgxpool.Pool, handlers map[string]StaleJobHandler, staleAfter time.Duration, logger *slog.Logger) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		// Roda IMEDIATAMENTE ao subir, antes de entrar no loop — mesmo
		// raciocínio de scanning.worker.PostureSnapshotLoop/
		// diario_oficial.worker.DiarioOficialSyncLoop: um job órfão
		// deixado por ANTES deste worker existir (ex.: o worker anterior
		// morreu, este é o substituto) merece ser recuperado assim que
		// alguém estiver de pé pra fazer isso, não só no primeiro tick
		// (staleAfter + sweepInterval depois).
		sweepOnce(ctx, pool, handlers, staleAfter, logger)

		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				sweepOnce(ctx, pool, handlers, staleAfter, logger)
			}
		}
	}
}

type staleJob struct {
	ID            uuid.UUID
	Type          string
	CorrelationID uuid.UUID
}

func sweepOnce(ctx context.Context, pool *pgxpool.Pool, handlers map[string]StaleJobHandler, staleAfter time.Duration, logger *slog.Logger) {
	cutoff := time.Now().Add(-staleAfter)
	rows, err := pool.Query(ctx, `SELECT id, type, correlation_id FROM jobs WHERE status = $1 AND started_at < $2`, StatusProcessing, cutoff)
	if err != nil {
		logger.Error("jobs: sweep stale jobs: query failed (best-effort, will retry next tick)", slog.Any("error", err))
		return
	}
	var stale []staleJob
	for rows.Next() {
		var j staleJob
		if err := rows.Scan(&j.ID, &j.Type, &j.CorrelationID); err != nil {
			logger.Error("jobs: sweep stale jobs: scan row failed", slog.Any("error", err))
			continue
		}
		stale = append(stale, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		logger.Error("jobs: sweep stale jobs: iterate rows failed", slog.Any("error", err))
		return
	}

	reason := fmt.Sprintf("stale: no activity since this job started processing more than %s ago — likely orphaned by a worker crash or restart mid-job, never a real retry exhaustion", staleAfter)
	for _, j := range stale {
		handler, ok := handlers[j.Type]
		if !ok {
			logger.Warn("jobs: sweep stale jobs: no StaleJobHandler registered for this job type, skipping",
				slog.String("job_id", j.ID.String()), slog.String("type", j.Type))
			continue
		}
		if err := handler(ctx, j.ID, j.CorrelationID, reason); err != nil {
			logger.Error("jobs: sweep stale jobs: handler failed (best-effort, will retry next tick)",
				slog.String("job_id", j.ID.String()), slog.String("type", j.Type), slog.Any("error", err))
			continue
		}
		logger.Warn("jobs: swept a stale job — marked as dead_letter (was stuck in \"processing\" with no worker activity)",
			slog.String("job_id", j.ID.String()), slog.String("type", j.Type))
	}
}
