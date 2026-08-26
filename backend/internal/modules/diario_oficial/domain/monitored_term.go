package domain

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Erros de validação de MonitoredTerm — mensagens estáveis o bastante
// pra virar apperrors.Validation(err.Error()) direto na camada
// application (ver application.CreateMonitoredTerm), sem precisar
// reformular texto nenhum ali.
var (
	errLabelRequired     = errors.New("label is required")
	errOABPairIncomplete = errors.New("oab_number and oab_uf must both be set, or both empty")
	errNoCriteria        = errors.New("at least one search criterion is required: oab_number+oab_uf, process_number, or free_text")
)

// MonitoredTerm é o que um usuário quer acompanhar no Diário Oficial —
// o equivalente desta plataforma ao "cadastro de OAB/processo" que todo
// produto de monitoramento jurídico (Jusbrasil, Escavador, Turivius, ...)
// oferece como funcionalidade central. Pelo menos um critério de busca
// precisa estar preenchido (ver Validate) — um termo sem nenhum nunca
// casaria com publicação nenhuma.
type MonitoredTerm struct {
	ID    uuid.UUID
	Label string
	// OABNumber/OABState: sempre juntos — o mesmo número de OAB se repete
	// entre estados, então um sem o outro seria uma busca ambígua (ver
	// HasOAB/Validate).
	OABNumber     string
	OABState      string
	ProcessNumber string
	FreeText      string
	Active        bool
	CreatedBy     *uuid.UUID
	// LastSyncedAt: até onde o worker já buscou pra este termo — nil
	// quando o termo nunca foi sincronizado (usa uma janela de lookback
	// fixa na primeira vez, ver application.syncSinceDate).
	LastSyncedAt *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// HasOAB reporta se t tem um par OAB+UF válido pra busca.
func (t MonitoredTerm) HasOAB() bool {
	return t.OABNumber != "" && t.OABState != ""
}

// HasAnyCriteria reporta se t tem pelo menos um critério de busca
// preenchido — a mesma regra que a CHECK constraint da migration 000026
// impõe no banco; validada aqui também pra rejeitar a entrada ANTES de
// gastar uma ida ao Postgres com um erro de constraint pouco amigável.
func (t MonitoredTerm) HasAnyCriteria() bool {
	return t.HasOAB() || t.ProcessNumber != "" || t.FreeText != ""
}

// Validate reporta o primeiro problema de dado encontrado, ou nil se t é
// válido pra persistir. Não inclui checagem de permissão/autorização —
// isso é responsabilidade da camada de transporte/aplicação.
func (t MonitoredTerm) Validate() error {
	if strings.TrimSpace(t.Label) == "" {
		return errLabelRequired
	}
	if (t.OABNumber == "") != (t.OABState == "") {
		return errOABPairIncomplete
	}
	if !t.HasAnyCriteria() {
		return errNoCriteria
	}
	return nil
}

// ToSearchQuery constrói a SearchQuery que representa este termo — since
// vem de fora (ver application.syncSinceDate, que decide a janela de
// lookback), não de LastSyncedAt diretamente: MonitoredTerm não sabe
// nada sobre política de sincronização, só sobre o QUE buscar.
func (t MonitoredTerm) ToSearchQuery(since *time.Time, page, pageSize int) SearchQuery {
	return SearchQuery{
		OABNumber:     t.OABNumber,
		OABState:      t.OABState,
		ProcessNumber: t.ProcessNumber,
		FreeText:      t.FreeText,
		Since:         since,
		Page:          page,
		PageSize:      pageSize,
	}
}
