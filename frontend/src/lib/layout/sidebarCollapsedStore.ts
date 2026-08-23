"use client";

// Pequena "external store" (no sentido de useSyncExternalStore) para o
// estado "Sidebar recolhida" persistido em localStorage — uma preferência
// puramente deste dispositivo/navegador (DashboardShell.tsx), sem
// precisar sincronizar entre abas nem chegar server-side (ao contrário do
// tema, que precisa — ver lib/theme/usePrefersDark.ts).
//
// Não é implementado como useState+useEffect porque ler localStorage e
// então chamar setState dentro de um efeito é exatamente o padrão que a
// regra de lint react-hooks/set-state-in-effect desencoraja — o React
// tem uma primitiva própria para "estado que vive fora do React e precisa
// re-renderizar quando muda": useSyncExternalStore. Este módulo é a
// "store" que ela espera: getSnapshot()/subscribe() sem efeito nenhum.
const STORAGE_KEY = "nix-sidebar-collapsed";

type Listener = () => void;
const listeners = new Set<Listener>();
let cached: boolean | null = null;

function read(): boolean {
  if (cached !== null) return cached;
  try {
    cached = window.localStorage.getItem(STORAGE_KEY) === "true";
  } catch {
    cached = false;
  }
  return cached;
}

export function getSidebarCollapsedSnapshot(): boolean {
  return read();
}

// SSR nunca teve uma preferência do dispositivo — assume expandida, igual
// ao comportamento anterior a esta mudança.
export function getSidebarCollapsedServerSnapshot(): boolean {
  return false;
}

export function setSidebarCollapsed(next: boolean): void {
  cached = next;
  try {
    window.localStorage.setItem(STORAGE_KEY, String(next));
  } catch {
    // Sem persistência nesta sessão (aba privada, política do navegador)
    // — a UI ainda reflete a escolha até a página recarregar.
  }
  listeners.forEach((listener) => listener());
}

export function subscribeSidebarCollapsed(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
