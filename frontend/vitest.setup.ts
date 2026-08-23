import "@testing-library/jest-dom/vitest";

// jsdom não implementa window.matchMedia — precisa de um stub mínimo para
// qualquer componente que leia prefers-color-scheme (ver
// lib/theme/usePrefersDark.ts, usado por ThemeToggle.tsx). Sempre reporta
// "não corresponde" (matches: false); testes que precisam simular um SO
// em modo escuro substituem isto pontualmente com vi.stubGlobal.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}
