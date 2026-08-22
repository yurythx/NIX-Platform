package ws

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestTicketStore_IssueThenRedeemOnce(t *testing.T) {
	store := NewTicketStore(time.Minute)
	defer store.Close()

	ticket, err := store.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if ticket.Value == "" {
		t.Fatal("expected a non-empty ticket value")
	}

	redeemed, err := store.Redeem(ticket.Value)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if redeemed.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", redeemed.UserID)
	}

	if _, err := store.Redeem(ticket.Value); err == nil {
		t.Fatal("expected redeeming the same ticket twice to fail")
	}
}

func TestTicketStore_ExpiredTicketRejected(t *testing.T) {
	store := NewTicketStore(10 * time.Millisecond)
	defer store.Close()

	ticket, err := store.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	time.Sleep(30 * time.Millisecond)

	if _, err := store.Redeem(ticket.Value); err == nil {
		t.Fatal("expected redeeming an expired ticket to fail")
	}
}

func TestTicketStore_UnknownTicketRejected(t *testing.T) {
	store := NewTicketStore(time.Minute)
	defer store.Close()

	if _, err := store.Redeem("does-not-exist"); err == nil {
		t.Fatal("expected redeeming an unknown ticket to fail")
	}
}

// testServer conecta um Hub + TicketStore reais atrás de httptest, para
// que os testes discem uma conexão WebSocket de verdade em vez de mockar
// qualquer coisa.
type testServer struct {
	server *httptest.Server
	hub    *Hub
	store  *TicketStore
	wsURL  string
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	hub := NewHub(testLogger())
	store := NewTicketStore(5 * time.Second)

	hubCtx, cancelHub := context.WithCancel(context.Background())
	go func() { _ = hub.Run(hubCtx) }()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", UpgradeHandler(hub, store, "", testLogger()))

	httpServer := httptest.NewServer(mux)
	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ws"

	t.Cleanup(func() {
		cancelHub()
		store.Close()
		httpServer.Close()
	})

	return &testServer{server: httpServer, hub: hub, store: store, wsURL: wsURL}
}

func TestUpgradeHandler_RejectsMissingTicket(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(strings.Replace(ts.wsURL, "ws", "http", 1)) //nolint:noctx
	if err != nil {
		t.Fatalf("GET /ws: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestUpgradeHandler_RejectsInvalidTicket(t *testing.T) {
	ts := newTestServer(t)

	u := ts.wsURL + "?ticket=bogus"
	_, resp, err := websocket.DefaultDialer.Dial(u, nil)
	if err == nil {
		t.Fatal("expected dial with an invalid ticket to fail")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestUpgradeHandler_ValidTicketConnectsAndReceivesBroadcast(t *testing.T) {
	ts := newTestServer(t)

	ticket, err := ts.store.Issue("user-42")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	u := ts.wsURL + "?ticket=" + url.QueryEscape(ticket.Value)
	conn, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Dá ao servidor um instante para terminar de registrar o cliente
	// antes de fazermos o broadcast — Start() registra de forma síncrona
	// antes das pumps rodarem, mas a entrega pelo canal register até o
	// Run() ainda é assíncrona.
	deadline := time.Now().Add(2 * time.Second)
	for ts.hub.ClientCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ts.hub.ClientCount() != 1 {
		t.Fatalf("hub.ClientCount() = %d, want 1", ts.hub.ClientCount())
	}

	ts.hub.Broadcast([]byte(`{"type":"notification.created"}`))

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if string(msg) != `{"type":"notification.created"}` {
		t.Errorf("received %q", msg)
	}
}

func TestUpgradeHandler_TicketIsSingleUse(t *testing.T) {
	ts := newTestServer(t)

	ticket, err := ts.store.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	u := ts.wsURL + "?ticket=" + url.QueryEscape(ticket.Value)

	conn1, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("first Dial: %v", err)
	}
	defer conn1.Close()

	if _, _, err := websocket.DefaultDialer.Dial(u, nil); err == nil {
		t.Fatal("expected reusing the same ticket for a second connection to fail")
	}
}
