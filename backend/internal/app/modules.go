package app

import (
	diarioApp "github.com/yurythx/nix-platform/internal/modules/diario_oficial/application"
	diarioInfra "github.com/yurythx/nix-platform/internal/modules/diario_oficial/infrastructure"
	diarioTransport "github.com/yurythx/nix-platform/internal/modules/diario_oficial/transport"

	integrationsApp "github.com/yurythx/nix-platform/internal/modules/integrations/application"
	integrationsInfra "github.com/yurythx/nix-platform/internal/modules/integrations/infrastructure"
	integrationsTransport "github.com/yurythx/nix-platform/internal/modules/integrations/transport"

	scanningApp "github.com/yurythx/nix-platform/internal/modules/scanning/application"
	scanningInfra "github.com/yurythx/nix-platform/internal/modules/scanning/infrastructure"
	scanningTransport "github.com/yurythx/nix-platform/internal/modules/scanning/transport"

	usersApp "github.com/yurythx/nix-platform/internal/modules/users/application"
	usersInfra "github.com/yurythx/nix-platform/internal/modules/users/infrastructure"
	usersTransport "github.com/yurythx/nix-platform/internal/modules/users/transport"

	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/configflags"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/localauth"
)

// Modules guarda o serviço de aplicação e os handlers HTTP de todo módulo
// de negócio. Construído uma vez por processo (cmd/api e cmd/worker cada
// um recebe o seu via NewDependencies) — este é o único arquivo autorizado
// a importar todo módulo de uma vez (§76), servindo como o "ponto de
// montagem" central que conecta domain/application/infrastructure/
// transport de cada módulo entre si e com a plataforma.
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
	Scanning struct {
		Service  *scanningApp.Service
		Handlers *scanningTransport.Handlers
	}
	ConfigFlags struct {
		Handlers *configflags.Handlers
	}
	LocalAuth struct {
		Handlers *localauth.Handlers
	}
}

// buildModules constrói cada módulo de negócio na ordem certa: primeiro
// as dependências compartilhadas (repositório de jobs, writer de
// auditoria), depois users e integrations (que não dependem de outros
// módulos), diario_oficial (que depende do integrationsSvc já construído
// para registrar o resultado de seus testes — ver
// internal/modules/integrations/application.Service.RecordCheckResult),
// e por fim scanning, que só depende do jobsRepo compartilhado e de todo
// domain.CodeScanner registrado (hoje: só o TrivyScanner).
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

	diarioClient := diarioInfra.NewHTTPClient(deps.Config.DiarioOficial.BaseURL, deps.Config.DiarioOficial.Timeout, deps.Logger)
	diarioSvc := diarioApp.NewService(deps.DB, jobsRepo, deps.Outbox, diarioClient, integrationsSvc, auditWriter, deps.Flags, deps.Logger)
	m.DiarioOficial.Service = diarioSvc
	m.DiarioOficial.Handlers = diarioTransport.NewHandlers(diarioSvc, deps.Logger)

	scanningRepo := scanningInfra.NewPostgresRepository(deps.DB)
	trivyScanner := scanningInfra.NewTrivyScanner(deps.Config.Scanning.TrivyPath, deps.Config.Scanning.CloneTimeout, deps.Logger)
	semgrepScanner := scanningInfra.NewSemgrepScanner(deps.Config.Scanning.SemgrepPath, deps.Config.Scanning.SemgrepConfig, deps.Config.Scanning.CloneTimeout, deps.Logger)
	sonarScanner := scanningInfra.NewSonarScanner(
		deps.Config.Scanning.SonarScannerPath, deps.Config.Scanning.SonarQubeURL, deps.Config.Scanning.SonarQubeToken,
		deps.Config.Scanning.CloneTimeout, deps.Config.Scanning.SonarQubeAnalysisTimeout, deps.Logger,
	)
	zapScanner := scanningInfra.NewZapScanner(
		deps.Config.Scanning.ZapURL, deps.Config.Scanning.ZapAPIKey, deps.Config.Scanning.ZapAllowedHosts,
		deps.Config.Scanning.ZapScanTimeout, deps.Logger,
	)
	scanningSvc := scanningApp.NewService(deps.DB, scanningRepo, jobsRepo, deps.Outbox, auditWriter, deps.Logger, trivyScanner, semgrepScanner, sonarScanner, zapScanner)
	m.Scanning.Service = scanningSvc
	m.Scanning.Handlers = scanningTransport.NewHandlers(scanningSvc, deps.Logger)

	m.ConfigFlags.Handlers = configflags.NewHandlers(deps.Flags, auditWriter, deps.Logger)

	localAuthStore := localauth.NewPostgresStore(deps.DB)
	m.LocalAuth.Handlers = localauth.NewHandlers(localAuthStore, deps.LocalSigner, auditWriter, deps.Logger)

	return m
}
