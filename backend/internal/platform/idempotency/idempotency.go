// Package idempotency implementa suporte a chaves de idempotência (padrão
// popularizado pela Stripe API) para endpoints HTTP que criam efeito
// colateral — hoje, os dois endpoints de criação de job assíncrono
// (POST .../diario-oficial/test e .../secops/virustotal/test). Sem isto,
// um duplo clique no botão "Testar" no dashboard, ou um retry automático
// de um cliente HTTP após um timeout de rede, cria dois jobs em vez de um
// — o segundo nunca sabendo que o primeiro já tinha sido aceito.
//
// Contrato: o cliente envia um header "Idempotency-Key" com um valor
// único por operação lógica (tipicamente um UUID gerado no cliente). A
// primeira requisição com uma chave nova é processada normalmente e sua
// resposta é guardada; toda requisição subsequente com a MESMA chave
// recebe de volta a resposta já guardada, em vez de reexecutar o caso de
// uso — mesmo que a operação original tenha efeitos colaterais (criar um
// job, publicar um evento de outbox). Requisições sem o header passam
// direto, sem nenhum custo extra — idempotência aqui é opt-in por
// requisição, não uma trava obrigatória.
package idempotency

import "context"

// Status é o estado de uma chave de idempotência ao longo do seu ciclo de
// vida: "processing" enquanto a requisição original ainda está sendo
// atendida, "completed" depois que ela termina com um status HTTP < 500
// (a resposta fica disponível para replay), "failed" se termina com
// status >= 500 (a chave é liberada para uma nova tentativa completa, já
// que uma falha de servidor não deve ser "lembrada" para sempre — o
// cliente pode tentar de novo esperando um resultado diferente).
type Status string

const (
	StatusProcessing Status = "processing"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
)

// Record é o estado persistido de uma chave de idempotência.
type Record struct {
	Key         string
	RequestHash string
	Status      Status

	// Populados apenas quando Status == StatusCompleted — é o que o
	// middleware reproduz (replay) para o cliente em vez de rodar o
	// handler de novo.
	ResponseStatus int
	ResponseBody   []byte
	ContentType    string
}

// Store persiste o estado das chaves de idempotência. A implementação de
// produção (PostgresStore) usa PostgreSQL — a plataforma não usa Redis
// por decisão arquitetural (§7) — mas o middleware depende só desta
// interface, o que permite testá-lo com uma implementação em memória sem
// nenhuma infraestrutura (ver middleware_test.go).
type Store interface {
	// Claim tenta reivindicar key para requestHash de forma atômica:
	//
	//   - Se key nunca foi vista, ou já está "failed" com o MESMO
	//     requestHash (permitindo uma nova tentativa completa depois de
	//     uma falha de servidor), Claim cria/reinicia o registro como
	//     "processing" e retorna claimed=true — quem chamou ganhou o
	//     direito de processar a requisição agora.
	//   - Caso contrário (key já está "processing" ou "completed", ou
	//     está "failed" mas com um requestHash DIFERENTE — sinal de que a
	//     chave está sendo reaproveitada para uma requisição diferente),
	//     Claim retorna claimed=false e existing com o registro atual,
	//     para o middleware decidir o que fazer (replay, 409, ou rejeitar
	//     por reuso indevido).
	//
	// A atomicidade é o que impede duas requisições concorrentes com a
	// mesma chave nova de ambas acharem que "ganharam" o direito de
	// processar.
	Claim(ctx context.Context, key, requestHash string) (existing *Record, claimed bool, err error)

	// Complete marca key como "completed" e guarda a resposta para
	// replay futuro. Chamado depois que o handler original termina com
	// um status HTTP < 500.
	Complete(ctx context.Context, key string, responseStatus int, responseBody []byte, contentType string) error

	// Fail marca key como "failed" — libera a chave para uma nova
	// tentativa completa. Chamado depois que o handler original termina
	// com um status HTTP >= 500, ou quando a resposta é grande demais
	// para ser guardada com segurança (ver MaxCachedResponseBytes).
	Fail(ctx context.Context, key string) error
}
