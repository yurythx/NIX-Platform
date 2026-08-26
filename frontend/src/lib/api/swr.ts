// Integração do apiClient com SWR (§ auditoria 2026-08, item "sem
// biblioteca de cache de dados") — usada só pelos Client Components que
// genuinamente precisam refazer uma busca depois do carregamento inicial
// (polling, um painel que abre sob demanda). A busca inicial de toda
// página continua em Server Components (app/(protected)/**/page.tsx) —
// SWR nunca substitui isso, só cobre o que "use client" + useEffect ainda
// faz de verdade depois da migração para RSC.
//
// Duas coisas que vinham faltando em todo useEffect manual espalhado
// pelo código (ver histórico de commits antes desta mudança), resolvidas
// de graça por usar SWRConfig com uma única configuração central em vez
// de duplicar fetch/loading/error em cada componente:
// - dedupe automático: dois componentes pedindo a MESMA key dentro da
//   janela de dedupingInterval reaproveitam a mesma requisição em voo.
// - revalidação ao focar a aba: sair e voltar pra aba busca de novo
//   sozinho, sem precisar de F5 (revalidateOnFocus, ligado por padrão do
//   SWR — nunca desligado aqui).
import useSWR, { type SWRConfiguration } from "swr";

import { apiClient, ApiError } from "@/lib/api/client";

// swrFetcher: a MESMA forma de erro que apiClient já lança (ApiError) —
// nenhum componente que já tratava ApiError (ver ProjectFindingHistoryPanel
// antes desta mudança) precisa de um caminho de erro diferente só porque
// a busca agora passa por SWR.
export async function swrFetcher<T>(path: string): Promise<T> {
  const { data } = await apiClient.get<T>(path);
  return data;
}

export { ApiError };

// defaultSWRConfig: aplicado uma vez via <SWRProvider> (ver swr-provider.tsx),
// não repetido em cada chamada de useSWR — mesmo princípio de
// design tokens centralizados em globals.css em vez de valores
// espalhados pelos componentes.
export const defaultSWRConfig: SWRConfiguration = {
  fetcher: swrFetcher,
  // Duas requisições pela mesma key dentro de 2s são a MESMA busca (ex.:
  // o card de status em /dashboard e uma aba de detalhe abrindo quase
  // juntos) — sem isso cada uma dispara sua própria requisição HTTP.
  dedupingInterval: 2000,
  // Um erro de rede/sessão expirada não deveria virar um loop de retry
  // agressivo contra um backend que já está com problema — mesmo
  // raciocínio que o client WebSocket já aplica (backoff, nunca retry
  // imediato).
  errorRetryCount: 2,
  shouldRetryOnError: (err) => !(err instanceof ApiError && err.status < 500),
};

// useApiQuery: wrapper fino sobre useSWR — passa swrFetcher diretamente
// (3º argumento de useSWR), não só via <SWRProvider>/SWRConfig: um
// componente renderizado sem o provider por perto (todo teste que só
// envolve com ToastProvider, por exemplo — ver TriggerScanForm.test.tsx)
// continua buscando dados de verdade em vez de silenciosamente nunca
// disparar nenhum fetch (useSWR sem fetcher nenhum, nem local nem via
// contexto, não é um erro — só fica com data sempre undefined pra
// sempre, o tipo de bug que só aparece rodando de verdade). SWRProvider
// continua valendo a pena por dedupingInterval/errorRetryCount
// compartilhados entre todo useApiQuery da área autenticada.
export function useApiQuery<T>(path: string | null, config?: SWRConfiguration<T>) {
  return useSWR<T>(path, swrFetcher, config);
}
