package ws

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Ticket is a short-lived, single-use credential that authorizes exactly
// one WebSocket upgrade (§38). Browsers cannot attach an Authorization
// header to a WebSocket handshake, and a long-lived access token in the
// URL would leak into logs/proxies, so the API mints one of these instead.
type Ticket struct {
	Value     string
	UserID    string
	ExpiresAt time.Time
	used      bool
}

// TicketStore issues and redeems tickets in-memory. This is intentionally
// single-instance (the platform has no Redis by design — §7); a
// multi-replica API deployment would need a shared store (e.g. a
// short-lived Postgres table) instead.
type TicketStore struct {
	mu      sync.Mutex
	tickets map[string]*Ticket
	ttl     time.Duration
	done    chan struct{}
}

// NewTicketStore builds a store whose tickets expire after ttl.
func NewTicketStore(ttl time.Duration) *TicketStore {
	s := &TicketStore{
		tickets: make(map[string]*Ticket),
		ttl:     ttl,
		done:    make(chan struct{}),
	}
	go s.evictExpiredLoop()
	return s
}

// Issue mints a new ticket for userID.
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

// Redeem validates and consumes a ticket. A ticket can be redeemed exactly
// once, and only before it expires.
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

// Close stops the background eviction loop.
func (s *TicketStore) Close() { close(s.done) }

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
