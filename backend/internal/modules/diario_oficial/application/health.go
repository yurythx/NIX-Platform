// Arquivo health.go — saúde da FONTE de dados (DJEN hoje, mais fontes no
// futuro quando uma prefeitura, por exemplo, entrar como segunda fonte —
// ver docs/roadmap-secops-orchestrator.md), pra uma tela poder mostrar
// "o provedor está respondendo?" ANTES do usuário estranhar por que
// nenhuma publicação nova apareceu. Mesmo espírito de
// scanning.Service.CheckScannersHealth (reestruturação de /seguranca),
// escopo bem menor aqui: só UMA fonte, não N scanners em paralelo.
package application

import (
	"context"
	"time"
)

// healthCheckTimeout: mesmo valor que scanning usa pra cada scanner — uma
// tela "a fonte está de pé?" precisa responder rápido mesmo se o DJEN
// estiver com uma conexão lenta/travada, não só fora do ar de vez.
const healthCheckTimeout = 5 * time.Second

// SourceHealth é o resultado de uma checagem de saúde de UMA fonte de
// dados. Source é uma string livre (não um enum fechado) de propósito —
// "djen" hoje, o que quer que uma integração futura (ex.: a API de uma
// prefeitura) se chame amanhã, sem precisar de uma mudança de schema
// pra acomodar um nome novo.
type SourceHealth struct {
	Source    string
	Healthy   bool
	Message   string
	CheckedAt time.Time
}

// CheckHealth confere se a fonte configurada (client.Check) está
// respondendo — nunca cria job, nunca grava nada, só uma leitura direta
// pra uma tela consultar sob demanda (ao contrário de CreateTestJob, que
// é assíncrono e pensado pra auditoria/notificação).
func (s *Service) CheckHealth(ctx context.Context) SourceHealth {
	checkCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	defer cancel()

	now := time.Now()
	result, err := s.client.Check(checkCtx)
	if err != nil {
		return SourceHealth{Source: "djen", Healthy: false, Message: err.Error(), CheckedAt: now}
	}
	return SourceHealth{Source: "djen", Healthy: true, Message: result.Summary, CheckedAt: now}
}
