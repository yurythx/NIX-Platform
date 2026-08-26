import Link from "next/link";

import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorState } from "@/components/ui/ErrorState";
import { Section } from "@/components/ui/Section";
import { NewProjectForm } from "@/components/scanning/NewProjectForm";
import { ProjectCard } from "@/components/scanning/ProjectCard";
import { ScannerHealthPanel } from "@/components/scanning/ScannerHealthPanel";
import { TriggerScanForm } from "@/components/scanning/TriggerScanForm";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { Project } from "@/types/api";

// /seguranca/novo (revisão de exibição de resultados — pedido do
// usuário: "ter um botão chamado novo scan que vai nos levar pra
// página que temos hj com as opções de scan"): esta página É "a que
// temos hoje" — TriggerScanForm + Projetos, tudo que já existia direto
// em /seguranca antes desta revisão, só movido pra sua própria rota.
// /seguranca virou a tela inicial (histórico de scans já feitos — ver
// aquela página), e um botão "Novo scan" leva pra cá.
//
// ScannerHealthPanel no topo (pedido do usuário: "uma tela onde mostra
// a saúde das ferramentas... antes de iniciá-las") — a primeira coisa
// que aparece, antes até do formulário, pra quem vai escolher scanner
// já saber se algum está fora do ar.
export default async function NovoScanPage() {
  let projects: Project[] = [];
  let projectsError: string | null = null;
  try {
    const { data } = await serverApiGet<Project[]>("v1/scanning/projects?limit=20");
    projects = data;
  } catch (err) {
    projectsError = err instanceof ApiError ? err.message : "Falha ao carregar projetos";
  }

  return (
    <div className="flex flex-col gap-8">
      <div>
        <Link href="/seguranca" className="text-sm text-primary hover:underline">
          ← Todos os scans
        </Link>
        <h1 className="mt-1 text-xl font-semibold">Novo scan</h1>
        <p className="text-sm text-muted">
          Dispare um scan (Trivy, Gitleaks, Syft, Semgrep, SonarQube, OWASP ZAP) contra um alvo
          avulso, ou reaproveite um projeto salvo abaixo.
        </p>
      </div>

      <ScannerHealthPanel />

      <TriggerScanForm />

      <Section
        title="Projetos"
        description="Salve um alvo pra rodar de novo depois sem digitar a URL (ou reanexar o .zip) toda vez."
      >
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
      </Section>
    </div>
  );
}
