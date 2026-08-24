import { describe, expect, it } from "vitest";

import { remediationFor } from "./remediation";

describe("remediationFor", () => {
  it("usa a orientação da categoria OWASP quando o achado tem uma", () => {
    const hint = remediationFor({ owasp_category: "A03:2021-Injection", scanner: "semgrep" });
    expect(hint).toMatch(/prepared statements|parametrizadas/i);
  });

  it("só o prefixo A0X:2021 importa, o nome depois do '-' é ignorado na busca", () => {
    const a = remediationFor({ owasp_category: "A06:2021-Vulnerable and Outdated Components", scanner: "trivy" });
    const b = remediationFor({ owasp_category: "A06:2021-Something Else Entirely", scanner: "trivy" });
    expect(a).toBe(b);
  });

  it("sem categoria OWASP, cai no texto específico do scanner (ex.: sonarqube, que nunca preenche a categoria)", () => {
    const hint = remediationFor({ owasp_category: "", scanner: "sonarqube" });
    expect(hint).toMatch(/sonarqube/i);
  });

  it("sem categoria OWASP e sem scanner conhecido, cai no texto genérico", () => {
    const hint = remediationFor({ owasp_category: "", scanner: "algum-scanner-futuro" });
    expect(hint).toMatch(/documentação da ferramenta/i);
  });
});
