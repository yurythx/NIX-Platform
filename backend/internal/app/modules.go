package app

import (
	diarioApp "github.com/yurythx/nix-platform/internal/modules/diario_oficial/application"
	diarioInfra "github.com/yurythx/nix-platform/internal/modules/diario_oficial/infrastructure"
	diarioTransport "github.com/yurythx/nix-platform/internal/modules/diario_oficial/transport"

	integrationsApp "github.com/yurythx/nix-platform/internal/modules/integrations/application"
	integrationsInfra "github.com/yurythx/nix-platform/internal/modules/integrations/infrastructure"
	integrationsTransport "github.com/yurythx/nix-platform/internal/modules/integrations/transport"

	secopsApp "github.com/yurythx/nix-platform/internal/modules/secops/application"
	secopsDomain "github.com/yurythx/nix-platform/internal/modules/secops/domain"
	"github.com/yurythx/nix-platform/internal/modules/secops/infrastructure/virustotal"
	secopsTransport "github.com/yurythx/nix-platform/internal/modules/secops/transport"

	usersApp "github.com/yurythx/nix-platform/internal/modules/users/application"
	usersInfra "github.com/yurythx/nix-platform/internal/modules/users/infrastructure"
	usersTransport "github.com/yurythx/nix-platform/internal/modules/users/transport"

	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
)

// Modules holds every business module's application service and HTTP
// handlers. Built once per process (cmd/api and cmd/worker each get their
// own via NewDependencies) — this is the only file allowed to import every
// module at once (§76).
type Modules struct {
	Users struct {
		Handlers *usersTransport.Handlers
	}
	Integrations struct {
		Service  *integrationsApp.Service
		Handlers *integrationsTransport.Handlers
	}
	DiarioOficial struct {
		Service  *diarioApp.Service
		Handlers *diarioTransport.Handlers
	}
	SecOps struct {
		Service  *secopsApp.Service
		Handlers *secopsTransport.Handlers
	}
}

func buildModules(deps *Dependencies) *Modules {
	jobsRepo := jobs.NewRepository(deps.DB)
	auditWriter := audit.NewWriter(deps.DB)

	m := &Modules{}

	usersRepo := usersInfra.NewPostgresRepository(deps.DB)
	usersSvc := usersApp.NewService(usersRepo, auditWriter)
	m.Users.Handlers = usersTransport.NewHandlers(usersSvc, deps.Logger, deps.Config.MaxPageSize)

	integrationsRepo := integrationsInfra.NewPostgresRepository(deps.DB)
	integrationsSvc := integrationsApp.NewService(integrationsRepo)
	m.Integrations.Service = integrationsSvc
	m.Integrations.Handlers = integrationsTransport.NewHandlers(integrationsSvc, deps.Logger)

	diarioClient := diarioInfra.NewHTTPClient(deps.Config.DiarioOficial.BaseURL, deps.Config.DiarioOficial.Timeout)
	diarioSvc := diarioApp.NewService(deps.DB, jobsRepo, deps.Outbox, diarioClient, integrationsSvc, auditWriter, deps.Logger)
	m.DiarioOficial.Service = diarioSvc
	m.DiarioOficial.Handlers = diarioTransport.NewHandlers(diarioSvc, deps.Logger)

	providers := map[string]secopsDomain.SecurityProvider{
		"virustotal": virustotal.NewClient(deps.Config.VirusTotal.APIKey, deps.Config.VirusTotal.BaseURL, deps.Config.VirusTotal.Timeout),
	}
	secopsSvc := secopsApp.NewService(deps.DB, jobsRepo, deps.Outbox, providers, integrationsSvc, auditWriter, deps.Logger)
	m.SecOps.Service = secopsSvc
	m.SecOps.Handlers = secopsTransport.NewHandlers(secopsSvc, deps.Logger)

	return m
}
