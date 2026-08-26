import { MatchedPublicationsFeed } from "@/components/diario-oficial/MatchedPublicationsFeed";
import { MonitoredTermsPanel } from "@/components/diario-oficial/MonitoredTermsPanel";
import { SourceHealthPanel } from "@/components/diario-oficial/SourceHealthPanel";
import { Section } from "@/components/ui/Section";

// /diario-oficial — MVP real de monitoramento do Diário Oficial (pedido
// do usuário: "quero saber como as grandes empresas especializadas
// fazem, quero aplicar as melhores implementações e as melhores
// práticas" — depois da exportação SARIF). Até aqui, diario_oficial só
// era um teste de conectividade dentro de /integracoes; esta é a
// primeira tela deste módulo que de fato faz o que Jusbrasil/Escavador/
// Turivius fazem: cadastrar um termo (OAB, processo, texto livre) e ver
// as publicações que casaram com ele, sincronizadas automaticamente
// contra o DJEN (Diário de Justiça Eletrônico Nacional, CNJ) pelo
// worker a cada 6h.
//
// Server Component só pelo casco da página — as duas seções são Client
// Components via SWR (ver MonitoredTermsPanel/MatchedPublicationsFeed):
// cadastrar/remover um termo precisa de feedback imediato na mesma
// lista, e o feed de publicações se beneficia de revalidar sozinho ao
// voltar pra aba, os dois motivos que já levaram ScannerHealthPanel
// (revisão de exibição de resultados) a essa mesma escolha.
export default function DiarioOficialPage() {
  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-xl font-semibold">Diário Oficial</h1>
        <p className="text-sm text-muted">
          Termos monitorados (OAB, número de processo ou texto livre) e as publicações que casaram
          com eles — sincronizado automaticamente contra o DJEN.
        </p>
      </div>

      <SourceHealthPanel />

      <Section title="Termos monitorados" description="O que está sendo acompanhado agora.">
        <MonitoredTermsPanel />
      </Section>

      <Section
        title="Publicações recentes"
        description="Mais recentes primeiro, entre todo termo monitorado."
      >
        <MatchedPublicationsFeed />
      </Section>
    </div>
  );
}
