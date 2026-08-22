// Package domain guarda o contrato do módulo diario_oficial com o sistema
// externo do Diário Oficial. A implementação HTTP real fica em
// infrastructure/ — este pacote não sabe nada sobre HTTP, RabbitMQ ou
// PostgreSQL.
package domain

import "context"

// CheckResult é o resultado de uma verificação bem-sucedida no Diário
// Oficial.
type CheckResult struct {
	StatusCode int
	Summary    string
}

// Client abstrai o sistema externo do Diário Oficial, para que a lógica de
// aplicação do módulo seja testável sem depender de um endpoint real —
// nos testes, uma implementação falsa (fake) desta interface substitui a
// chamada HTTP de verdade.
type Client interface {
	Check(ctx context.Context) (*CheckResult, error)
}
