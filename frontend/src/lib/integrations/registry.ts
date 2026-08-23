// Registro de integrações (§ Integrações como menu próprio): a única
// peça de metadado que o frontend precisa saber sobre cada integração
// além do que GET /api/v1/integrations já devolve — o endpoint de teste
// e uma frase descrevendo o que o teste faz. Uma integração sem entrada
// aqui ainda ganha uma página de detalhe funcional (via
// integracoes/[key]/page.tsx) — só não mostra o botão "Testar conexão",
// já que não haveria pra onde apontá-lo. Nenhuma configuração
// EDITÁVEL (chave de API, endpoint) mora aqui — isso ainda é feito via
// variável de ambiente do backend; expor isso como formulário só faz
// sentido quando existir um endpoint de verdade pra persistir a mudança.
export interface IntegrationRegistryEntry {
  description: string;
  testPath: string;
}

export const integrationRegistry: Record<string, IntegrationRegistryEntry> = {
  "diario-oficial": {
    description:
      "Executa uma verificação assíncrona de conectividade com o endpoint configurado do Diário Oficial.",
    testPath: "v1/integrations/diario-oficial/test",
  },
};
