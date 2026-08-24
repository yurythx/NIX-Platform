import { describe, expect, it } from "vitest";

import type { ScanFinding } from "@/types/api";

import { buildAIPrompt } from "./aiPrompt";

function makeFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    id: "f1",
    scan_id: "scan-1",
    scanner: "trivy",
    target: "https://github.com/org/repo.git",
    finding_id: "CVE-2026-0001",
    owasp_category: "A06:2021-Vulnerable and Outdated Components",
    severity: "HIGH",
    description: "dependência vulnerável",
    file: "go.sum",
    line: 12,
    fingerprint: "abc123fingerprint",
    created_at: "2026-08-24T12:00:00Z",
    tool: { name: "Trivy" },
    ...overrides,
  };
}

describe("buildAIPrompt", () => {
  it("inclui os dados essenciais do achado", () => {
    const prompt = buildAIPrompt(makeFinding());
    expect(prompt).toContain("Trivy");
    expect(prompt).toContain("HIGH");
    expect(prompt).toContain("A06:2021-Vulnerable and Outdated Components");
    expect(prompt).toContain("CVE-2026-0001");
    expect(prompt).toContain("go.sum:12");
    expect(prompt).toContain("dependência vulnerável");
  });

  it("inclui a orientação de remediationFor (contexto que a proposta original não tinha)", () => {
    const prompt = buildAIPrompt(makeFinding());
    expect(prompt).toMatch(/atualize a dependência/i);
  });

  it("inclui o snippet quando presente, formatado como bloco de código", () => {
    const prompt = buildAIPrompt(makeFinding({ snippet: "10: foo()\n11: bar()\n12: eval(x)" }));
    expect(prompt).toContain("```");
    expect(prompt).toContain("12: eval(x)");
  });

  it("sem snippet, não inclui a seção de trecho do código", () => {
    const prompt = buildAIPrompt(makeFinding({ snippet: undefined }));
    expect(prompt).not.toContain("Trecho do código");
  });

  it("sem local (file vazio), mostra 'não aplicável' em vez de um \":0\" sem sentido", () => {
    const prompt = buildAIPrompt(makeFinding({ file: "", line: 0 }));
    expect(prompt).toContain("não aplicável");
  });

  it("sem categoria OWASP, omite a linha de categoria em vez de mostrar vazia", () => {
    const prompt = buildAIPrompt(makeFinding({ owasp_category: "" }));
    expect(prompt).not.toContain("**Categoria OWASP:**");
  });
});
