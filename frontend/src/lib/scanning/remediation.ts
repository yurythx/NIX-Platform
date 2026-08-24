// remediationFor dá uma orientação genérica de correção pra um achado de
// segurança — o "como corrigir" pedido explicitamente pelo usuário,
// junto de "qual ferramenta achou o erro" (finding.scanner, já exposto
// como coluna própria em /seguranca) e "que tipo de erro"
// (finding.owasp_category, idem).
//
// A orientação é por CATEGORIA do OWASP Top 10 2021, não por CVE/regra
// individual: as 4 ferramentas (Trivy/Semgrep/SonarQube/ZAP) juntas
// podem reportar milhares de CVEs e regras diferentes — cobrir cada uma
// exigiria uma base de dados própria e permanentemente desatualizada. O
// Top 10 já é a simplificação que a própria indústria de segurança usa
// pra esse nível de generalidade, e é o mesmo formato
// ("A0X:2021-<nome>") que domain.Finding.OWASPCategory já carrega no
// backend (ver scanning/infrastructure/{trivy,zap}_scanner.go) — nenhum
// mapeamento novo precisou ser inventado, só a orientação de texto por
// prefixo. SonarQube nunca preenche OWASPCategory (comentário confirmado
// contra a API real em sonar_scanner.go) — por isso o fallback por
// SCANNER abaixo, pra nenhum achado ficar sem nenhuma orientação.
const remediationByOwaspCategory: Record<string, string> = {
  "A01:2021":
    "Revise as regras de controle de acesso do trecho apontado — quem pode acessar esse recurso deveria, e ninguém mais. Prefira negar por padrão e checar a permissão explicitamente, nunca confiar em campos que o próprio cliente controla.",
  "A02:2021":
    "Dados sensíveis (senhas, tokens, segredos) precisam estar cifrados em trânsito e em repouso, com um algoritmo/força atuais — nunca em texto puro, nunca com um algoritmo já quebrado.",
  "A03:2021":
    "Nunca monte comandos/consultas concatenando entrada do usuário direto na string — use consultas parametrizadas/prepared statements (SQL), escaping adequado (HTML/shell), ou uma API que não interprete a entrada como código.",
  "A04:2021":
    "Isso costuma ser uma falha de DESIGN, não só de código — revise se o próprio fluxo de negócio já previne o abuso (limites de taxa, validação de regras de negócio), não só a implementação pontual.",
  "A05:2021":
    "Confira a configuração do serviço/imagem apontado: credenciais padrão, portas/serviços desnecessários expostos, headers de segurança ausentes, mensagem de erro vazando detalhe interno.",
  "A06:2021":
    "Atualize a dependência/imagem base pra uma versão sem a vulnerabilidade — o identificador do achado (geralmente um CVE) já aponta exatamente qual. Sem versão corrigida ainda, considere uma mitigação temporária (WAF, isolar o componente) até existir uma.",
  "A07:2021":
    "Revise o fluxo de autenticação: senha fraca permitida, falta de limite de tentativas, sessão que não expira ou não é invalidada no logout.",
  "A08:2021":
    "Confirme a integridade do que está sendo carregado/desserializado (assinatura, checksum) antes de confiar no conteúdo — especialmente em pipelines de CI/CD e atualizações automáticas.",
  "A09:2021":
    "Garanta que eventos de segurança relevantes (login, falha de autenticação, ação administrativa) fiquem registrados e sejam monitorados — sem isso, um incidente pode passar despercebido.",
  "A10:2021":
    "Nunca deixe o servidor buscar uma URL fornecida pelo cliente sem validar o destino — a mesma defesa que este backend já aplica ao alvo de um scan (rejeitando IPs privados/internos antes de clonar) é o padrão a seguir.",
};

const remediationByScanner: Record<string, string> = {
  trivy: "Consulte o identificador do achado (geralmente um CVE, campo \"Achado\" acima) na base de dados da ferramenta ou no advisory do próprio pacote, para a versão corrigida.",
  semgrep:
    "Consulte a regra do achado (campo \"Achado\" acima, ex.: go.lang.security.audit.sql-injection) no Semgrep Registry para o padrão de correção recomendado.",
  sonarqube:
    "Abra o achado direto no SonarQube (a chave da regra está no campo \"Achado\" acima) — a própria ferramenta já traz a explicação e um exemplo de correção pra cada regra.",
  zap: "Consulte o alerta do ZAP (campo \"Achado\" acima) na documentação do OWASP ZAP para o passo a passo de mitigação — achados de DAST costumam exigir mudança na aplicação em execução, não só no código-fonte.",
};

const genericRemediation =
  "Sem uma categoria OWASP conhecida associada a este achado — revise a descrição e a documentação da ferramenta indicada em \"Scanner\" para orientação específica.";

export function remediationFor(finding: { owasp_category: string; scanner: string }): string {
  // "A03:2021-Injection" -> "A03:2021": só o prefixo entra na busca, o
  // nome da categoria depois do "-" já aparece por si só na coluna
  // "Categoria OWASP" da tabela.
  const prefix = finding.owasp_category.split("-")[0];
  if (prefix && remediationByOwaspCategory[prefix]) {
    return remediationByOwaspCategory[prefix];
  }
  return remediationByScanner[finding.scanner] ?? genericRemediation;
}
