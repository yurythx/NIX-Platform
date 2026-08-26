// Testes de monitoring.go. syncSinceDate é pura (roda sempre, sem
// Postgres); os demais exercitam application.Service completo (termo +
// sync + match + outbox) contra o Postgres real usado por todo este
// backend, pulando se TEST_DATABASE_URL não estiver definida — mesmo
// padrão de service_test.go.
package application

import (
	"context"
	"testing"
	"time"

	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
	"github.com/yurythx/nix-platform/internal/platform/configflags"
)

func TestSyncSinceDate_NeverSynced_UsesLookbackWindow(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	term := domain.MonitoredTerm{}

	got := syncSinceDate(term, now)
	want := now.Add(-defaultLookbackWindow)
	if !got.Equal(want) {
		t.Errorf("syncSinceDate = %v, want %v (lookback de %v)", got, want, defaultLookbackWindow)
	}
}

func TestSyncSinceDate_AlreadySynced_OverlapsFromLastSync(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	lastSync := now.Add(-3 * 24 * time.Hour)
	term := domain.MonitoredTerm{LastSyncedAt: &lastSync}

	got := syncSinceDate(term, now)
	want := lastSync.Add(-syncOverlapWindow)
	if !got.Equal(want) {
		t.Errorf("syncSinceDate = %v, want %v (last sync menos a margem de sobreposição)", got, want)
	}
}

// searchByPageClient simula o DJEN devolvendo itens em páginas, pra
// exercitar o loop de paginação de syncTerm sem depender de rede real.
type searchByPageClient struct {
	checkErr error
	pages    [][]domain.SearchResultItem
	calls    int
}

func (c *searchByPageClient) Check(context.Context) (*domain.CheckResult, error) {
	return nil, c.checkErr
}

func (c *searchByPageClient) Search(ctx context.Context, query domain.SearchQuery) (*domain.SearchResult, error) {
	c.calls++
	idx := query.Page - 1
	if idx < 0 || idx >= len(c.pages) {
		return &domain.SearchResult{}, nil
	}
	return &domain.SearchResult{Items: c.pages[idx], TotalCount: len(c.pages)}, nil
}

func TestCreateMonitoredTerm_InvalidTerm_ReturnsValidationError(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeClient{})

	_, err := svc.CreateMonitoredTerm(context.Background(), domain.MonitoredTerm{}, nil)
	if err == nil {
		t.Fatal("expected a validation error for a term with no label and no criteria")
	}
}

func TestCreateMonitoredTerm_Valid_PersistsAndIsListed(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeClient{})
	ctx := context.Background()

	created, err := svc.CreateMonitoredTerm(ctx, domain.MonitoredTerm{Label: "Dr. Fulano — OAB/MG 419", OABNumber: "419", OABState: "MG"}, nil)
	if err != nil {
		t.Fatalf("CreateMonitoredTerm: %v", err)
	}
	if !created.Active {
		t.Error("a newly created term should be Active by default")
	}

	terms, err := svc.ListMonitoredTerms(ctx)
	if err != nil {
		t.Fatalf("ListMonitoredTerms: %v", err)
	}
	found := false
	for _, term := range terms {
		if term.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Error("newly created term not found in ListMonitoredTerms")
	}
}

func TestDeleteMonitoredTerm_RemovesIt(t *testing.T) {
	pool := testPool(t)
	svc := newService(pool, &fakeClient{})
	ctx := context.Background()

	created, err := svc.CreateMonitoredTerm(ctx, domain.MonitoredTerm{Label: "x", ProcessNumber: "123"}, nil)
	if err != nil {
		t.Fatalf("CreateMonitoredTerm: %v", err)
	}

	if err := svc.DeleteMonitoredTerm(ctx, created.ID, nil); err != nil {
		t.Fatalf("DeleteMonitoredTerm: %v", err)
	}

	terms, err := svc.ListMonitoredTerms(ctx)
	if err != nil {
		t.Fatalf("ListMonitoredTerms: %v", err)
	}
	for _, term := range terms {
		if term.ID == created.ID {
			t.Error("deleted term still appears in ListMonitoredTerms")
		}
	}
}

// TestSyncAll_NewMatch_PersistsPublicationMatchAndOutboxEvent é o teste
// de ponta a ponta do MVP: termo cadastrado -> SyncAll busca no DJEN
// (fake, controlado) -> publicação + match gravados -> evento
// diario_oficial.publication.matched no outbox -> re-sincronizar não
// duplica nada (idempotência via ON CONFLICT DO NOTHING nas duas
// tabelas).
func TestSyncAll_NewMatch_PersistsPublicationMatchAndOutboxEvent(t *testing.T) {
	pool := testPool(t)
	client := &searchByPageClient{pages: [][]domain.SearchResultItem{
		{{
			ExternalID: 999001, Tribunal: "TJMG", Orgao: "1ª Vara Cível", TipoComunicacao: "Intimação",
			Texto: "publicação de teste", ProcessNumber: "123", ProcessNumberMasked: "0000123-45.2026.8.13.0001",
			AvailabilityDate: time.Now(), RawPayload: []byte(`{"id":999001}`),
		}},
	}}
	svc := newService(pool, client)
	ctx := context.Background()

	term, err := svc.CreateMonitoredTerm(ctx, domain.MonitoredTerm{Label: "termo de teste sync", OABNumber: "419", OABState: "MG"}, nil)
	if err != nil {
		t.Fatalf("CreateMonitoredTerm: %v", err)
	}

	svc.SyncAll(ctx)

	items, _, err := svc.ListPublicationsForTerm(ctx, term.ID, 1, 20)
	if err != nil {
		t.Fatalf("ListPublicationsForTerm: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("publications for term = %d, want 1", len(items))
	}
	if items[0].Tribunal != "TJMG" {
		t.Errorf("Tribunal = %q, want TJMG", items[0].Tribunal)
	}

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE event_type = $1 AND aggregate_id = $2`,
		EventPublicationMatched, items[0].ID).Scan(&n); err != nil {
		t.Fatalf("count outbox events: %v", err)
	}
	if n == 0 {
		t.Error("expected a diario_oficial.publication.matched outbox event")
	}

	// Segundo ciclo: mesma publicação, mesmo termo — não deveria
	// duplicar publicação nem match nem gerar um segundo evento.
	svc.SyncAll(ctx)

	itemsAfter, _, err := svc.ListPublicationsForTerm(ctx, term.ID, 1, 20)
	if err != nil {
		t.Fatalf("ListPublicationsForTerm (segundo ciclo): %v", err)
	}
	if len(itemsAfter) != 1 {
		t.Errorf("publications for term após segundo ciclo = %d, want 1 (sem duplicar)", len(itemsAfter))
	}

	var nAfter int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE event_type = $1 AND aggregate_id = $2`,
		EventPublicationMatched, items[0].ID).Scan(&nAfter); err != nil {
		t.Fatalf("count outbox events (segundo ciclo): %v", err)
	}
	if nAfter != n {
		t.Errorf("outbox events após segundo ciclo = %d, want %d (sem notificar de novo)", nAfter, n)
	}
}

func TestSyncAll_InactiveTerm_IsNotSynced(t *testing.T) {
	pool := testPool(t)
	client := &searchByPageClient{pages: [][]domain.SearchResultItem{
		{{ExternalID: 999002, Tribunal: "TJSP", AvailabilityDate: time.Now(), RawPayload: []byte(`{}`)}},
	}}
	svc := newService(pool, client)
	ctx := context.Background()

	term, err := svc.CreateMonitoredTerm(ctx, domain.MonitoredTerm{Label: "termo inativo", ProcessNumber: "999888"}, nil)
	if err != nil {
		t.Fatalf("CreateMonitoredTerm: %v", err)
	}
	// Desativa direto no repositório de infraestrutura (não há endpoint
	// de "pausar" nesta primeira versão — ver roadmap).
	if _, err := pool.Exec(ctx, `UPDATE diario_oficial_monitored_terms SET active = false WHERE id = $1`, term.ID); err != nil {
		t.Fatalf("deactivate term: %v", err)
	}

	svc.SyncAll(ctx)

	if client.calls != 0 {
		t.Errorf("Search called %d times, want 0 (termo inativo não deveria ser sincronizado)", client.calls)
	}
}

func TestSyncAll_FeatureDisabled_SkipsEntirely(t *testing.T) {
	pool := testPool(t)
	client := &searchByPageClient{}
	svc := newServiceWithFlags(pool, client, fakeFlagsDisabled{})
	ctx := context.Background()

	if _, err := svc.CreateMonitoredTerm(ctx, domain.MonitoredTerm{Label: "x", ProcessNumber: "1"}, nil); err != nil {
		t.Fatalf("CreateMonitoredTerm: %v", err)
	}

	svc.SyncAll(ctx)

	if client.calls != 0 {
		t.Errorf("Search called %d times, want 0 (feature flag desabilitada)", client.calls)
	}
}

// fakeFlagsDisabled sempre reporta a flag como desabilitada — o inverso
// do nil (nil = sempre permitido, ver NewService) usado pelo resto desta
// suíte.
type fakeFlagsDisabled struct{}

func (fakeFlagsDisabled) IsEnabled(context.Context, string, bool) (bool, error) { return false, nil }
func (fakeFlagsDisabled) List(context.Context) ([]configflags.Flag, error)      { return nil, nil }
func (fakeFlagsDisabled) Set(context.Context, string, bool, string) (configflags.Flag, error) {
	return configflags.Flag{}, nil
}
