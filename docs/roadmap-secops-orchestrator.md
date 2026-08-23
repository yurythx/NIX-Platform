# Roadmap — SecOps Orchestrator: Trivy, Semgrep, TruffleHog, SonarQube e OWASP ZAP como parte do NIX Platform

- **Status:** Fase 1 (Fundação) implementada — ver detalhes na seção "Fases" abaixo. Fases 2+
  (as ferramentas externas de verdade: TruffleHog, Trivy, Semgrep, SonarQube, OWASP ZAP) seguem
  propostas; a decisão de qual atacar primeiro é do usuário.
- **Origem:** adaptação de uma proposta externa (Core em Go orquestrando ferramentas SecOps via
  Microkernel/Strategy/Adapter/Observer) para a arquitetura real deste repositório.
- **Revisão:** a primeira versão deste documento usava o módulo `secops`/VirusTotal como exemplo
  vivo de cada padrão já implementado. Esse módulo foi removido do produto (decisão do usuário —
  era a única integração "SecOps" real, e o rumo daqui pra frente é o orquestrador desenhado
  abaixo, não um provedor de lookup avulso). Os exemplos abaixo foram trocados para
  `diario_oficial`, o único módulo de integração restante — a arquitetura de plataforma que os
  patterns abaixo reaproveitam (outbox, circuit breaker, feature flags, auditoria) não mudou.

## Por que isto não é um "Core" novo — é uma extensão do que já existe

A proposta original pede um núcleo em Go do zero, gerenciando ferramentas de segurança como
plug-ins. O NIX Platform **já tem a espinha dorsal de plataforma** que isso precisa — o que não
existe mais é um exemplo vivo do papel específico de "Strategy" (não há mais um segundo provedor
plugável hoje, só `diario_oficial`, que fala com um único endpoint fixo) — mas a infraestrutura
em volta continua real e reaproveitável:

| Padrão pedido na proposta | Onde já existe no NIX Platform hoje |
|---|---|
| Strategy Pattern (interface comum por ferramenta) | ✅ Implementado na Fase 1: `scanning/domain/scanner.go` define `CodeScanner`; nenhuma implementação real ainda registrada (só o `fakeScanner` de teste) até a Fase 2 trazer a primeira ferramenta de verdade. |
| Adapter Pattern (normalizar o output de cada ferramenta) | `diario_oficial/infrastructure/http_client.go` traduz a resposta HTTP do endpoint configurado pro modelo próprio do módulo — mesmo princípio (isolar o formato de terceiros do resto do sistema), aplicado a um único parceiro em vez de vários. Cada scanner real (Fase 2+) ganha seu próprio adapter em `scanning/infrastructure/`. |
| Observer / Event-Driven | Outbox transacional + RabbitMQ (`internal/platform/outbox`, `internal/domain/events`) já publicam `integration.status.changed`, `diario_oficial.job.completed/failed` e, desde a Fase 1, `scanning.scan.completed` — ainda sem nenhum consumer real deste último. |
| Microkernel / plug-in registry | ✅ Implementado na Fase 1: `scanning.Service` recebe `...domain.CodeScanner` no construtor e monta um `map[string]CodeScanner` internamente — registrar uma ferramenta nova (Fase 2+) é só passar mais um argumento no wiring de `internal/app`, sem tocar em `RunScan`. |
| Resiliência (timeout, circuit breaker) | `internal/platform/resilience` (circuit breaker) e `context.Context` com timeout já protegem toda chamada externa — o mesmo mecanismo cobre um scanner novo sem código extra. |
| Interruptor de emergência por ferramenta | `internal/platform/configflags` (feature flags em runtime) já desliga uma integração inteira sem reimplantar — `diario_oficial_scraping_enabled` é o exemplo vivo hoje; cada scanner novo ganha sua própria flag do mesmo jeito. |
| Auditoria de cada execução | `internal/platform/audit` (log imutável) já registra toda ação sensível — cada scan vira uma entrada de auditoria como qualquer outra. |

**A diferença real que exige código novo:** um lookup de "essa entidade é maliciosa? sim/não"
(o que o `secops` removido fazia) cabe num resultado único. Trivy/Semgrep/TruffleHog/SonarQube
devolvem uma **lista** de achados discretos (um scan pode encontrar 40 vulnerabilidades, cada
uma com seu próprio CVE/arquivo/linha/severidade) — um formato estruturalmente diferente, que a
interface `CodeScanner` da Fase 1 já nasce pensando nisso, em vez de tentar encaixar numa forma
de resultado único.

## Arquitetura adaptada

Novo módulo `internal/modules/scanning` (mesmo padrão de pastas de todo módulo já existente:
`domain/application/infrastructure/transport`), com sua própria tabela (`scan_findings`),
suas próprias permissões RBAC (`scanning:read`, `scanning:manage`, seguindo o padrão já usado —
ver `internal/platform/auth/rbac.go`) e reaproveitando toda a plataforma já construída — nada
disso é modificado, só consumido:

```mermaid
flowchart LR
    subgraph scanning["internal/modules/scanning (novo)"]
        Iface["CodeScanner interface\n(Strategy)"]
        Trivy["TrivyAdapter"]
        Semgrep["SemgrepAdapter"]
        TruffleHog["TruffleHogAdapter"]
        Sonar["SonarQubeAdapter"]
        Zap["ZapAdapter"]
        Iface -.implementa.-> Trivy & Semgrep & TruffleHog & Sonar & Zap
    end
    Service["scanning.Service\n(Microkernel)"] --> Iface
    Service --> Outbox["outbox transacional\n(já existe)"]
    Service --> Breaker["circuit breaker\n(já existe)"]
    Service --> Flags["feature flags\n(já existe)"]
    Outbox --> RabbitMQ["RabbitMQ\n(já existe)"]
    RabbitMQ --> WS["WebSocket -> frontend\n(já existe)"]
    Service --> Audit["audit log\n(já existe)"]
```

`CodeScanner` (a interface nova, Fase 1):

```go
package scanning

type Severity string

const (
    SeverityCritical Severity = "CRITICAL"
    SeverityHigh     Severity = "HIGH"
    SeverityMedium   Severity = "MEDIUM"
    SeverityLow      Severity = "LOW"
)

// Finding é o modelo unificado de achado — todo adaptador converte o
// formato nativo da sua ferramenta (JSON/XML/SARIF) pra isto.
type Finding struct {
    ID          string   // CVE-2026-XXXX, ou uma regra própria (ex.: "semgrep:go.lang.security.audit.sql-injection")
    OWASPCategory string // "A03:2021-Injection", etc. — ver o mapeamento abaixo
    Severity    Severity
    Description string
    File        string // vazio para achados que não são de arquivo (ex.: DAST)
    Line        int
}

// CodeScanner é o contrato que toda ferramenta de scanning implementa —
// desenhado desde já pra "lista de achados" (não um resultado único),
// já que é isso que Trivy/Semgrep/TruffleHog/SonarQube/ZAP produzem.
type CodeScanner interface {
    Name() string
    Execute(ctx context.Context, target string) ([]Finding, error)
}
```

## Fases

Cada fase entrega algo testável e revertível por conta própria — nenhuma depende de todas as
ferramentas estarem prontas para gerar valor.

**Fase 1 — Fundação (sem ferramenta externa nenhuma ainda) — ✅ implementada**
- Migration `scan_findings` (id, scanner, target, owasp_category, severity, description, file,
  line, created_at) — mesmo padrão das tabelas já existentes
  (`migrations/000014_scan_findings.sql`).
- Interface `CodeScanner` + modelo `Finding` (acima) — `scanning/domain/scanner.go`, junto com
  `Repository` (persistência dos achados).
- `scanning.Service` (Strategy + Microkernel): recebe `map[string]CodeScanner` (registrado no
  construtor, um `panic` em nome duplicado — erro de wiring, não condição de runtime), roda um
  scan e grava achados + evento de outbox `scanning.scan.completed` numa única transação
  (`scanning/application/service.go`).
  - **Desvio deliberado do texto acima**: `RunScan` é **síncrono**, não o mesmo desenho
    assíncrono job+outbox+worker de `diario_oficial.Service.CreateTestJob`. O padrão assíncrono
    existe para desacoplar uma requisição HTTP de uma operação lenta via fila — mas esta fase não
    cria nenhum endpoint HTTP nem consumer de fila (ver abaixo), então um job/worker aqui seria
    infraestrutura morta: mensagens publicadas que nada consome. `RunScan` grava achados + evento
    de outbox atomicamente e retorna direto, sem fila no meio. A Fase 2, ao introduzir o primeiro
    scanner real chamado a partir de um endpoint HTTP de verdade, é o momento certo de revisitar
    essa escolha.
- Testado inteiramente com um `fakeScanner`, do mesmo jeito que
  `diario_oficial/application/service_test.go` já testa contra Postgres real com um `fakeClient`
  — nenhuma ferramenta externa precisa estar instalada para esta fase passar no CI
  (`scanning/application/service_test.go`, pulado sem `TEST_DATABASE_URL`).
- RBAC: `scanning:read`/`scanning:manage` adicionadas a `rbac.go`, concedidas a
  `nix-integration-manager` (leitura+gestão) e `nix-auditor` (só leitura) — o mesmo par de roles
  que já cobre integrações, em vez de um role novo só para isto.
- Auditoria: `audit.ActionScanCompleted` (`"scan.completed"`) registrado a cada `RunScan`.
- **Deliberadamente fora desta fase** (chega com o primeiro scanner real, Fase 2+): nenhum
  endpoint HTTP/transport, nenhuma fila/worker RabbitMQ, nenhuma UI no frontend, e o módulo
  `scanning` ainda **não está conectado** em `internal/app/modules.go` — não há nenhum
  `CodeScanner` real para registrar nele ainda, e conectar um `Service` sem nenhum scanner nem
  chamador seria abstração morta (o mesmo raciocínio que levou à remoção completa do módulo
  `secops`/VirusTotal).

**Fase 2 — TruffleHog (secret scanning)**
- ⚠️ **Observação de engenharia antes de implementar**: o CI deste projeto já roda
  [gitleaks](https://github.com/gitleaks/gitleaks) (`.github/workflows/gitleaks.yml`) — a mesma
  categoria de ferramenta que o TruffleHog. Rodar os dois é redundante sem ganho claro. Duas
  opções pra decidir antes de começar esta fase: (a) adotar TruffleHog e aposentar o job do
  gitleaks, ou (b) manter gitleaks no CI (já funciona, já está configurado) e usar esta fase pra
  outro scanner da lista. Este roadmap assume (a) por seguir literalmente a proposta original,
  mas é uma escolha do usuário, não uma conclusão técnica.
- `TruffleHogAdapter`: roda via `os/exec` chamando o binário instalado no container do worker
  (mesmo padrão de spawnar processo já usado por nenhum código atual — seria a primeira vez que
  o backend chama um binário externo, então vale revisar com cuidado: timeout via
  `context.Context`, `stderr` capturado pro log, nunca repassar o output bruto pro cliente). Se
  em vez disso rodar como container (mais isolado, mas mais pesado), a dependência nova seria o
  SDK do Docker (`github.com/docker/docker/client`) — não está no `go.mod` hoje, então essa
  escolha (processo local vs. container) é a primeira decisão real desta fase.

**Fase 3 — Trivy (dependências, containers, IaC)**
- Menor risco de implementação: o Trivy **já roda no CI** (`ci.yml`, escaneando as 3 imagens
  Docker finais) — esta fase reaproveita o mesmo binário/imagem, só que disparado sob demanda
  pelo `scanning.Service` em vez de só no pipeline.
- `TrivyAdapter`: escaneia `go.mod`/`package-lock.json` (dependências), Dockerfiles, e a própria
  imagem construída — três alvos, um adaptador (o parâmetro `target` já distingue).

**Fase 4 — Semgrep (SAST)**
- `SemgrepAdapter`: exatamente como no exemplo da proposta original (`os/exec` chamando
  `semgrep scan --json`), convertendo pra `[]Finding`. Regras: usar o registry público
  (`p/owasp-top-ten`, mantido pela comunidade Semgrep) como ponto de partida.

**Fase 5 — SonarQube (qualidade de código, bugs)**
- **Maior custo de infraestrutura da lista**: exige um servidor SonarQube rodando (self-hosted
  via Docker Compose, ou SonarCloud). Avaliar esse custo operacional antes de começar — é a
  única fase que não é "só chamar um binário."

**Fase 6 — OWASP ZAP (DAST)**
- **Maior risco de todas as fases**: dispara ataques ativos contra um alvo rodando de verdade.
  Regra inegociável: `ZapAdapter` só pode apontar para ambientes de homologação/staging,
  nunca produção — reforçado por uma allowlist de hosts no próprio Core (o mesmo princípio do
  Gateway Pattern que a proposta cita para mitigar A10/SSRF, aplicado aqui na direção inversa:
  não deixar o próprio scanner virar um vetor de ataque contra o alvo errado).

**Fase 7 — Orquestração concorrente**
- Rodar scanners independentes em paralelo via goroutines + `errgroup`, com timeout por
  `context.Context` cancelando um scanner que trava sem derrubar os outros — o mesmo raciocínio
  que já rege o circuit breaker existente, estendido para paralelismo.

**Fase 8 — CLI + CI/CD**
- Um subcomando novo (`cmd/secscan`, mesmo padrão de `cmd/api`/`cmd/worker`) chamável como
  `nix-secscan scan --repo .` — usado tanto localmente quanto no `ci.yml`, unificando o que hoje
  são 4 jobs de CI separados (govulncheck, npm audit, Trivy, gitleaks/CodeQL) atrás de uma única
  interface, sem remover nenhum deles.

**Fase 9 — Frontend**
- Uma aba nova em `/integracoes` (ou uma seção própria) listando achados recentes por severidade
  — reaproveitando `IntegrationCard`/`StatusIndicator`/o padrão de Server Component já em uso em
  todo o resto do dashboard, não um design novo.

## Mapeamento OWASP Top 10 — o que já é real hoje vs. o que este roadmap adiciona

| Risco | Já implementado no NIX Platform hoje | O que este roadmap adiciona |
|---|---|---|
| A01 Broken Access Control | RBAC por permissão (`RequirePermission`), rotas sensíveis protegidas | ZAP testando fuzzing de IDs em staging (Fase 6) |
| A02 Cryptographic Failures | RS256 próprio pro login local, bcrypt, segredos via `_FILE`, HSTS | — (já coberto; scanners não mudam isso) |
| A03 Injection | 100% consultas parametrizadas via pgx (conferido nesta sessão: zero concatenação de string em SQL) | Semgrep com taint analysis automatizado (Fase 4) |
| A04 Insecure Design | Monólito modular com fronteiras de módulo, ADRs documentando decisão de arquitetura | — (prática de engenharia, não uma ferramenta) |
| A05 Security Misconfiguration | CSP com nonce, headers de segurança, containers non-root | Trivy varrendo Dockerfile/Terraform sob demanda (Fase 3) |
| A06 Vulnerable Components | govulncheck + npm audit + Trivy (imagens) + Dependabot, todos já no CI | Trivy sob demanda fora do CI também (Fase 3) |
| A07 Auth Failures | Bloqueio de conta, rate limit distribuído, erro genérico (sem enumeração de usuário) | ZAP testando o ciclo de vida de sessão em staging (Fase 6) |
| A08 Software & Data Integrity | Idempotência, outbox transacional, CI builda a partir do código-fonte | Nenhuma assinatura/SBOM ainda — gap real, não coberto por nenhuma fase acima; ficaria fora de escopo deste roadmap |
| A09 Logging & Monitoring | Audit log imutável, logs estruturados correlacionados por request id, Prometheus, OpenTelemetry | `scanning.scan.completed` como mais um evento auditado (Fase 1) |
| A10 SSRF | Nenhum endpoint aceita URL arbitrária do chamador (conferido nesta sessão) — risco estruturalmente baixo hoje | Semgrep detectando clientes HTTP com URL não validada, se esse padrão aparecer no futuro (Fase 4) |

## Fora de escopo deste roadmap

- Assinatura digital de artefatos / SBOM (A08) — mencionado na proposta original, mas é um
  projeto à parte (ferramenta tipo `cosign`/`syft`), não uma fase natural deste orquestrador.
- Qualquer execução automática deste roadmap nesta sessão — este documento é o planejamento;
  implementação começa quando o usuário escolher uma fase.
