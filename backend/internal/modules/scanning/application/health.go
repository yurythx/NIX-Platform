// Arquivo health.go (revisão de exibição de resultados — "quero ter uma
// tela onde mostra a saúde das ferramentas que estamos usando antes de
// iniciá-las"): CheckScannersHealth roda a checagem de TODO scanner
// registrado que implementa domain.HealthChecker (hoje, os 6) em
// paralelo, com um timeout curto por scanner — pensado pra alimentar
// uma tela que o usuário olha ANTES de disparar um scan, então precisa
// responder rápido mesmo se um sidecar estiver travado, não só fora do
// ar.
package application

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// healthCheckTimeout: bem mais curto que o timeout normal de um scan —
// a tela "antes de iniciar" precisa responder rápido, mesmo que um
// sidecar esteja travado (não só fora do ar, que responderia rejeitando
// a conexão quase instantaneamente de qualquer forma).
const healthCheckTimeout = 5 * time.Second

// ScannerHealth é o resultado da checagem de UM scanner — ver
// domain.HealthChecker.
type ScannerHealth struct {
	Scanner   string
	Healthy   bool
	Message   string // vazio quando Healthy; o texto do erro caso contrário
	CheckedAt time.Time
}

// CheckScannersHealth checa todo scanner registrado que implementa
// domain.HealthChecker, em paralelo — a ordem do resultado é sempre por
// nome do scanner (não a ordem de conclusão, que variaria a cada
// chamada só por causa de qual sidecar respondeu primeiro). Um scanner
// registrado que NÃO implementa HealthChecker (não deveria acontecer —
// os 6 registrados hoje implementam todos) simplesmente não aparece no
// resultado, em vez de um item "sem verificação disponível" — quem
// exibe isto já sabe montar a tela só com o que veio.
func (s *Service) CheckScannersHealth(ctx context.Context) []ScannerHealth {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []ScannerHealth
	)

	for name, scanner := range s.scanners {
		checker, ok := scanner.(domain.HealthChecker)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(name string, checker domain.HealthChecker) {
			defer wg.Done()
			checkCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
			defer cancel()

			err := checker.HealthCheck(checkCtx)
			health := ScannerHealth{Scanner: name, Healthy: err == nil, CheckedAt: time.Now()}
			if err != nil {
				health.Message = err.Error()
			}

			mu.Lock()
			results = append(results, health)
			mu.Unlock()
		}(name, checker)
	}

	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Scanner < results[j].Scanner })
	return results
}
