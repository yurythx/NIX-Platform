import { remediationFor } from "./remediation";
import { scannerMeta } from "./scannerRegistry";
import type { ScanFinding } from "@/types/api";

// buildAIPrompt monta o markdown do botão "Copiar prompt pra IA" (Fase
// 13) — o mesmo formato que a proposta original especificava (seção
// 5.C), com um acréscimo real: também inclui remediationFor() (o hint
// por categoria OWASP que este roadmap já gera desde a Fase 9), contexto
// a mais que a proposta não tinha porque não existia antes disso ser
// construído. Puro (sem navigator.clipboard aqui dentro) — só monta o
// texto, quem chama decide como copiar (ver FindingsTable.tsx).
export function buildAIPrompt(finding: ScanFinding): string {
  const tool = scannerMeta(finding.scanner).name || finding.tool.name;
  const location = finding.file
    ? finding.file + (finding.line > 0 ? `:${finding.line}` : "")
    : "não aplicável";

  const lines = [
    "Você é um especialista em segurança de aplicações. Analise o achado abaixo e sugira uma correção completa.",
    "",
    `**Ferramenta:** ${tool}`,
    `**Severidade:** ${finding.severity}`,
  ];
  if (finding.owasp_category) {
    lines.push(`**Categoria OWASP:** ${finding.owasp_category}`);
  }
  lines.push(`**Achado:** ${finding.finding_id}`, `**Local:** ${location}`, "", "**Descrição:**", finding.description);

  if (finding.snippet) {
    lines.push("", "**Trecho do código:**", "```", finding.snippet, "```");
  }

  lines.push("", "**Orientação geral:**", remediationFor(finding));
  lines.push(
    "",
    "Explique a causa raiz do problema e proponha uma correção concreta (incluindo o código corrigido, quando aplicável).",
  );

  return lines.join("\n");
}
