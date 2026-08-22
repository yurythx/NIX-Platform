package ws

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Ticket é uma credencial de curta duração e uso único que autoriza
// exatamente um upgrade de WebSocket (§38). Navegadores não conseguem
// anexar um header Authorization ao handshake de WebSocket, e um access
// token de vida longa na URL vazaria em logs/proxies, então a API emite um
// destes em vez disso.
type Ticket struct {
	Value     string
	UserID    string
	ExpiresAt time.Time
	used      bool
}

// TicketStore emite e resgata tickets em memória. É deliberadamente
// single-instance (a plataforma não tem Redis por decisão de arquitetura —
// §7); um deployment de API com múltiplas réplicas precisaria de um
// armazenamento compartilhado (ex.: uma tabela de vida curta no Postgres,
// no mesmo espírito do internal/platform/ratelimit.PostgresLimiter) em vez
// deste. Como o ticket é resgatado quase imediatamente após ser emitido
// (o navegador abre o WebSocket logo depois de receber o ticket via HTTP),
// na prática o risco de a réplica errada não conhecer o ticket é baixo,
// mas é uma limitação documentada, não um esquecimento.
type TicketStore struct {
	mu      sync.Mutex
	tickets map[string]*Ticket
	ttl     time.Duration
	done    chan struct{}
}

// NewTicketStore constrói um store cujos tickets expiram depois de ttl.
func NewTicketStore(ttl time.Duration) *TicketStore {
	s := &TicketStore{
		tickets: make(map[string]*Ticket),
		ttl:     ttl,
		done:    make(chan struct{}),
	}
	go s.evictExpiredLoop()
	return s
}

// Issue emite um novo ticket para userID.
func (s *TicketStore) Issue(userID string) (*Ticket, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("ws: generate ticket: %w", err)
	}

	t := &Ticket{
		Value:     hex.EncodeToString(raw),
		UserID:    userID,
		ExpiresAt: time.Now().Add(s.ttl),
	}

	s.mu.Lock()
	s.tickets[t.Value] = t
	s.mu.Unlock()

	return t, nil
}

// Redeem valida e consome um ticket. Um ticket só pode ser resgatado
// exatamente uma vez, e apenas antes de expirar — a segunda tentativa de
// uso do mesmo valor (replay) é sempre rejeitada.
func (s *TicketStore) Redeem(value string) (*Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tickets[value]
	if !ok {
		return nil, fmt.Errorf("ws: unknown or already-redeemed ticket")
	}
	if t.used {
		return nil, fmt.Errorf("ws: ticket already used")
	}
	if time.Now().After(t.ExpiresAt) {
		delete(s.tickets, value)
		return nil, fmt.Errorf("ws: ticket expired")
	}

	t.used = true
	delete(s.tickets, value)
	return t, nil
}

// Close para o loop de remoção em segundo plano.
func (s *TicketStore) Close() { close(s.done) }

// evictExpiredLoop remove periodicamente tickets expirados que nunca
// chegaram a ser resgatados, para que o mapa não cresça indefinidamente
// com tickets emitidos mas nunca usados (ex.: cliente que fechou a aba
// antes de abrir o WebSocket).
func (s *TicketStore) evictExpiredLoop() {
	ticker := time.NewTicker(s.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, t := range s.tickets {
				if now.After(t.ExpiresAt) {
					delete(s.tickets, k)
				}
			}
			s.mu.Unlock()
		}
	}
}
