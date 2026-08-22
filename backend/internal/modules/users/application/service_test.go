package application

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/users/domain"
)

type fakeRepository struct {
	bySubject map[string]*domain.User
}

func newFakeRepository() *fakeRepository {
	return &fakeRepository{bySubject: map[string]*domain.User{}}
}

func (f *fakeRepository) UpsertByKeycloakSubject(ctx context.Context, u *domain.User) (domain.UpsertResult, error) {
	if existing, ok := f.bySubject[u.KeycloakSubject]; ok {
		existing.Username = u.Username
		existing.Email = u.Email
		return domain.UpsertResult{User: existing, Created: false}, nil
	}
	u.ID = uuid.New()
	f.bySubject[u.KeycloakSubject] = u
	return domain.UpsertResult{User: u, Created: true}, nil
}

func (f *fakeRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	for _, u := range f.bySubject {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, errNotFound{}
}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func (f *fakeRepository) List(ctx context.Context, p pagination.Params) ([]*domain.User, int64, error) {
	var out []*domain.User
	for _, u := range f.bySubject {
		out = append(out, u)
	}
	return out, int64(len(out)), nil
}

func TestGetCurrentUser_CreatesOnFirstSight(t *testing.T) {
	repo := newFakeRepository()
	svc := NewService(repo, nil)

	user, err := svc.GetCurrentUser(context.Background(), SyncIdentityInput{
		Subject: "sub-1", Username: "jdoe", Email: "jdoe@example.com",
	})
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if user.Username != "jdoe" {
		t.Errorf("Username = %q", user.Username)
	}
	if len(repo.bySubject) != 1 {
		t.Errorf("expected exactly one stored user, got %d", len(repo.bySubject))
	}
}

func TestGetCurrentUser_UpdatesOnSubsequentSight(t *testing.T) {
	repo := newFakeRepository()
	svc := NewService(repo, nil)
	ctx := context.Background()

	first, err := svc.GetCurrentUser(ctx, SyncIdentityInput{Subject: "sub-1", Username: "jdoe", Email: "jdoe@old.com"})
	if err != nil {
		t.Fatalf("first GetCurrentUser: %v", err)
	}

	second, err := svc.GetCurrentUser(ctx, SyncIdentityInput{Subject: "sub-1", Username: "jdoe", Email: "jdoe@new.com"})
	if err != nil {
		t.Fatalf("second GetCurrentUser: %v", err)
	}

	if second.ID != first.ID {
		t.Error("expected the same user id across repeated sightings")
	}
	if second.Email != "jdoe@new.com" {
		t.Errorf("Email = %q, want updated value", second.Email)
	}
	if len(repo.bySubject) != 1 {
		t.Errorf("expected still exactly one stored user, got %d", len(repo.bySubject))
	}
}

func TestGetCurrentUser_RejectsEmptySubject(t *testing.T) {
	svc := NewService(newFakeRepository(), nil)
	if _, err := svc.GetCurrentUser(context.Background(), SyncIdentityInput{}); err == nil {
		t.Fatal("expected an error for an empty subject")
	}
}
