import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { PostureSnapshot } from "@/types/api";

import { PostureTrendChart } from "./PostureTrendChart";

function snapshot(overrides: Partial<PostureSnapshot> = {}): PostureSnapshot {
  return {
    date: "2026-08-01",
    open_critical: 0,
    open_high: 0,
    open_medium: 0,
    open_low: 0,
    triaged_count: 0,
    projects_scanned: 1,
    ...overrides,
  };
}

describe("PostureTrendChart", () => {
  it("com menos de 2 pontos, mostra a mensagem de histórico insuficiente, nunca um gráfico vazio/quebrado", () => {
    render(<PostureTrendChart snapshots={[snapshot()]} />);
    expect(screen.getByText(/ainda não há histórico suficiente/i)).toBeInTheDocument();
  });

  it("com 0 pontos, também mostra a mensagem (não quebra com array vazio)", () => {
    render(<PostureTrendChart snapshots={[]} />);
    expect(screen.getByText(/ainda não há histórico suficiente/i)).toBeInTheDocument();
  });

  it("com 2+ pontos, desenha o SVG com a data mais antiga e mais recente", () => {
    render(
      <PostureTrendChart
        snapshots={[
          snapshot({ date: "2026-08-01", open_critical: 2, open_high: 1 }),
          snapshot({ date: "2026-08-15", open_critical: 1, open_high: 3 }),
        ]}
      />,
    );
    expect(screen.getByRole("img", { name: /tendência/i })).toBeInTheDocument();
    expect(screen.getByText(new Date("2026-08-01").toLocaleDateString())).toBeInTheDocument();
    expect(screen.getByText(new Date("2026-08-15").toLocaleDateString())).toBeInTheDocument();
  });
});
