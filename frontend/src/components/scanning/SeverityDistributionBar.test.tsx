import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SeverityDistributionBar } from "./SeverityDistributionBar";

describe("SeverityDistributionBar", () => {
  it("sem nenhum achado (todos os contadores zerados), não renderiza nada", () => {
    const { container } = render(
      <SeverityDistributionBar counts={{ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("com achados, expõe a distribuição no rótulo acessível", () => {
    render(<SeverityDistributionBar counts={{ CRITICAL: 2, HIGH: 1, MEDIUM: 0, LOW: 3 }} />);
    const bar = screen.getByRole("img", { name: /2 crítico, 1 alto, 0 médio, 3 baixo/ });
    expect(bar).toBeInTheDocument();
  });

  it("uma severidade com zero achados não vira um segmento (sem largura 0% no DOM)", () => {
    render(<SeverityDistributionBar counts={{ CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0 }} />);
    const bar = screen.getByRole("img");
    // Só CRITICAL tem achado — só 1 filho (o segmento vermelho), não 4.
    expect(bar.children).toHaveLength(1);
  });
});
