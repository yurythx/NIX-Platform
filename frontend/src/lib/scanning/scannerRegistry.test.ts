import { describe, expect, it } from "vitest";

import { scannerMeta, SCANNERS } from "./scannerRegistry";

describe("scannerMeta", () => {
  it("conhece os 6 scanners registrados no backend", () => {
    const keys = SCANNERS.map((s) => s.key).sort();
    expect(keys).toEqual(["gitleaks", "semgrep", "sonarqube", "syft", "trivy", "zap"]);
  });

  it("todo scanner registrado tem nome, categoria, descrição e instrução de uso não vazios", () => {
    for (const s of SCANNERS) {
      expect(s.name).not.toBe("");
      expect(s.category).not.toBe("");
      expect(s.description).not.toBe("");
      expect(s.usage).not.toBe("");
    }
  });

  it("um scanner desconhecido (futuro, ainda sem entrada) devolve um fallback genérico, nunca undefined", () => {
    const meta = scannerMeta("um-scanner-futuro");
    expect(meta.key).toBe("um-scanner-futuro");
    expect(meta.name).toBe("um-scanner-futuro");
  });
});
