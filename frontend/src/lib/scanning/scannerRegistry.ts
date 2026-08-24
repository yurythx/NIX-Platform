// Registro dos scanners (mesmo espírito de lib/integrations/registry.ts):
// a única fonte de nome de exibição/categoria/descrição/instrução de uso
// de cada scanner no frontend — TriggerScanForm (cards de seleção),
// ScanProgress (cards de progresso) e ToolFindingsCards (cards de achado
// por ferramenta) usam este MESMO registro, pra nunca divergir em nome
// entre as três telas. Não há endpoint "listar scanners disponíveis" no
// backend, então esta lista é mantida manualmente em sincronia com
// docs/openapi.yaml — mesmo princípio já documentado no registro de
// integrações.
export interface ScannerMeta {
  key: string;
  name: string;
  category: string;
  description: string;
  usage: string;
}

export const SCANNERS: ScannerMeta[] = [
  {
    key: "trivy",
    name: "Trivy",
    category: "Dependências e Dockerfiles",
    description:
      "Escaneia dependências (go.mod, package.json, requirements.txt, ...) e Dockerfiles em busca de vulnerabilidades conhecidas (CVEs) e configurações inseguras de container.",
    usage:
      "Alvo: URL https:// de um repositório git, opcionalmente com #branch (ex.: https://github.com/org/repo.git#main). Clona o repositório e analisa os arquivos de dependência/Dockerfile encontrados.",
  },
  {
    key: "semgrep",
    name: "Semgrep",
    category: "SAST — análise estática de código",
    description:
      "Analisa o CÓDIGO-FONTE em busca de padrões inseguros conhecidos (injeção, criptografia fraca, segredo hardcoded, ...) usando o ruleset OWASP Top 10.",
    usage:
      "Alvo: URL https:// de um repositório git, opcionalmente com #branch. Clona o repositório e roda as regras contra todo o código-fonte encontrado.",
  },
  {
    key: "sonarqube",
    name: "SonarQube",
    category: "Qualidade de código e SAST",
    description:
      "Análise de qualidade de código: bugs, code smells, complexidade cognitiva/ciclomática, duplicação, além de vulnerabilidades de segurança. O resultado também fica disponível na própria UI do SonarQube deste ambiente.",
    usage:
      "Alvo: URL https:// de um repositório git, opcionalmente com #branch. Clona o repositório e envia a análise pro servidor SonarQube — resultado consultável aqui e diretamente na ferramenta (ver \"Abrir na ferramenta\" no detalhe de cada achado).",
  },
  {
    key: "zap",
    name: "OWASP ZAP",
    category: "DAST — ataca de verdade",
    description:
      "Ataca um serviço web JÁ RODANDO (não código-fonte) em busca de vulnerabilidades em tempo de execução — XSS, cabeçalhos de segurança ausentes, e outras falhas só visíveis com a aplicação de pé.",
    usage:
      "Alvo: URL http(s) de um serviço já rodando, alcançável pelo worker — nunca uma URL git. Só ataca hosts explicitamente autorizados (SCANNING_ZAP_ALLOWED_HOSTS), nunca produção.",
  },
];

const byKey = new Map(SCANNERS.map((s) => [s.key, s]));

// scannerMeta nunca retorna undefined — um scanner sem entrada no
// registro (ex.: adicionado no backend antes de ganhar uma entrada aqui)
// ainda recebe um nome/descrição genéricos, nunca uma tela quebrada.
export function scannerMeta(key: string): ScannerMeta {
  return (
    byKey.get(key) ?? {
      key,
      name: key,
      category: "",
      description: "",
      usage: "",
    }
  );
}
