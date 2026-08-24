import { ErrorState } from "@/components/ui/ErrorState";
import { EmptyState } from "@/components/ui/EmptyState";
import { FindingsTable } from "@/components/scanning/FindingsTable";
import { NewProjectForm } from "@/components/scanning/NewProjectForm";
import { ProjectCard } from "@/components/scanning/ProjectCard";
import { ScanList } from "@/components/scanning/ScanList";
import { TriggerScanForm } from "@/components/scanning/TriggerScanForm";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { Project, ScanFinding, ScanStatus } from "@/types/api";

// Segurança (Fase 9 do roadmap de segurança —
// docs/roadmap-secops-orchestrator.md): originalmente só um feed de
// achados entre TODOS os scans, sem separação nenhuma por execução.
// Pedido do usuário: "quero os resultados separados por scan... quero
// poder clicar neles de forma individual e ver os detalhes". Agora duas
// seções — Scans recentes (ScanList, cada entrada com seu próprio link
// pra /seguranca/[scanId], onde o progresso ao vivo e o detalhe de cada
// achado desse scan específico vivem) e Achados recentes (FindingsTable,
// a visão AGREGADA entre todos os scans, que continua útil pra achar "o
// que há de mais grave em qualquer lugar" sem precisar abrir scan por
// scan — cada linha aqui também clicável, com showScanLink levando de
// volta pro scan de origem).
//
// TriggerScanForm (Client Component) dispara um scan novo e já mostra o
// progresso ao vivo ali mesmo, com um link pra página de detalhe própria
// desse job — a resposta mais direta a "resultados separados por scan":
// o resultado de CADA disparo já nasce na sua própria URL, não misturado
// num feed genérico.
export default async function SegurancaPage() {
  let scans: ScanStatus[] = [];
  let scansError: string | null = null;
  try {
    const { data } = await serverApiGet<ScanStatus[]>("v1/scanning/scans?limit=20");
    scans = data;
  } catch (err) {
    scansError = err instanceof ApiError ? err.message : "Falha ao carregar scans recentes";
  }

  let findings: ScanFinding[] = [];
  let findingsError: string | null = null;
  try {
    const { data } = await serverApiGet<ScanFinding[]>("v1/scanning/findings?limit=100");
    findings = data;
  } catch (err) {
    findingsError = err instanceof ApiError ? err.message : "Falha ao carregar achados";
  }

  // projects (Fase 10 — Projeto persistente + upload .zip): best-effort,
  // mesmo princípio das outras duas buscas acima — uma falha aqui não
  // deveria impedir o resto da página (scans/achados) de renderizar.
  let projects: Project[] = [];
  let projectsError: string | null = null;
  try {
    const { data } = await serverApiGet<Project[]>("v1/scanning/projects?limit=20");
    projects = data;
  } catch (err) {
    projectsError = err instanceof ApiError ? err.message : "Falha ao carregar projetos";
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Segurança</h1>
        <p className="text-sm text-muted">
          Dispare um scan (Trivy, Gitleaks, Syft, Semgrep, SonarQube, OWASP ZAP), acompanhe o
          progresso e veja os achados de cada execução, separadamente.
        </p>
      </div>

      <TriggerScanForm />

      <div>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">Projetos</h2>
        <div className="flex flex-col gap-4">
          <NewProjectForm />
          {projectsError ? (
            <ErrorState message={projectsError} />
          ) : projects.length === 0 ? (
            <EmptyState
              title="Nenhum projeto ainda"
              description="Crie um acima pra rodar o mesmo alvo de novo depois sem digitar a URL (ou reanexar o .zip) toda vez."
            />
          ) : (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {projects.map((p) => (
                <ProjectCard key={p.id} project={p} />
              ))}
            </div>
          )}
        </div>
      </div>

      <div>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">
          Scans recentes
        </h2>
        {scansError ? <ErrorState message={scansError} /> : <ScanList scans={scans} />}
      </div>

      <div>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">
          Achados recentes (todos os scans)
        </h2>
        {findingsError ? (
          <ErrorState message={findingsError} />
        ) : (
          <FindingsTable findings={findings} showScanLink />
        )}
      </div>
    </div>
  );
}
