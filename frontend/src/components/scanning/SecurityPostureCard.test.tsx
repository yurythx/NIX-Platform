import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { SecurityPosture } from "@/types/api";

import { SecurityPostureCard } from "./SecurityPostureCard";

function posture(overrides: Partial<SecurityPosture> = {}): SecurityPosture {
  return {
    open_critical: 0,
    open_high: 0,
    open_medium: 0,
    open_low: 0,
    triaged_count: 0,
    projects_scanned: 0,
    top_vulnerable: [],
    ...overrides,
  };
}

describe("SecurityPostureCard", () => {
  it("nenhum projeto escaneado ainda mostra o EmptyState, não zeros", () => {
    render(<SecurityPostureCard posture={posture()} />);
    expect(screen.getByText("Nenhum projeto escaneado ainda")).toBeInTheDocument();
  });

  it("com achados abertos, mostra os selos de severidade e a contagem de projetos", () => {
    render(
      <SecurityPostureCard
        posture={posture({ open_critical: 2, open_high: 3, projects_scanned: 5, triaged_count: 1 })}
      />,
    );
    expect(screen.getByText("2 crítico(s)")).toBeInTheDocument();
    expect(screen.getByText("3 alto(s)")).toBeInTheDocument();
    expect(screen.getByText(/5 projeto\(s\) escaneado\(s\)/)).toBeInTheDocument();
    expect(screen.getByText(/1 achado\(s\) triado\(s\)/)).toBeInTheDocument();
  });

  it("projeto escaneado mas sem achado aberto nenhum mostra 'Nenhum achado aberto', não o EmptyState", () => {
    render(<SecurityPostureCard posture={posture({ projects_scanned: 3 })} />);
    expect(screen.getByText("Nenhum achado aberto")).toBeInTheDocument();
    expect(screen.queryByText("Nenhum projeto escaneado ainda")).not.toBeInTheDocument();
  });

  it("lista os projetos mais vulneráveis com sua contagem de crítico/alto", () => {
    render(
      <SecurityPostureCard
        posture={posture({
          projects_scanned: 1,
          open_critical: 1,
          top_vulnerable: [{ project_id: "p1", project_name: "meu-projeto", open_critical: 1, open_high: 2 }],
        })}
      />,
    );
    expect(screen.getByText("meu-projeto")).toBeInTheDocument();
    expect(screen.getByText("1 crítico(s), 2 alto(s)")).toBeInTheDocument();
  });

  it("sem history (prop ausente), não mostra a seção 'Tendência'", () => {
    render(<SecurityPostureCard posture={posture({ projects_scanned: 1 })} />);
    expect(screen.queryByText("Tendência")).not.toBeInTheDocument();
  });

  it("com history vazio ([]), também não mostra a seção 'Tendência' (nada pra desenhar ainda)", () => {
    render(<SecurityPostureCard posture={posture({ projects_scanned: 1 })} history={[]} />);
    expect(screen.queryByText("Tendência")).not.toBeInTheDocument();
  });

  it("com history preenchido, mostra a seção 'Tendência' com o gráfico", () => {
    render(
      <SecurityPostureCard
        posture={posture({ projects_scanned: 1 })}
        history={[
          { date: "2026-08-01", open_critical: 2, open_high: 1, open_medium: 0, open_low: 0, triaged_count: 0, projects_scanned: 1 },
          { date: "2026-08-15", open_critical: 1, open_high: 1, open_medium: 0, open_low: 0, triaged_count: 0, projects_scanned: 1 },
        ]}
      />,
    );
    expect(screen.getByText("Tendência")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /tendência/i })).toBeInTheDocument();
  });
});
