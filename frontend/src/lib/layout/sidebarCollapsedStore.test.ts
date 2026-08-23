import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  getSidebarCollapsedServerSnapshot,
  getSidebarCollapsedSnapshot,
  setSidebarCollapsed,
  subscribeSidebarCollapsed,
} from "./sidebarCollapsedStore";

describe("sidebarCollapsedStore", () => {
  beforeEach(() => {
    window.localStorage.clear();
    // O módulo mantém um cache em memória entre chamadas dentro do mesmo
    // processo de teste — força a releitura do localStorage limpo acima
    // gravando explicitamente o estado inicial esperado.
    setSidebarCollapsed(false);
  });

  it("getServerSnapshot é sempre false (SSR nunca tem preferência do dispositivo)", () => {
    expect(getSidebarCollapsedServerSnapshot()).toBe(false);
  });

  it("persiste a escolha em localStorage e reflete no snapshot", () => {
    setSidebarCollapsed(true);
    expect(getSidebarCollapsedSnapshot()).toBe(true);
    expect(window.localStorage.getItem("nix-sidebar-collapsed")).toBe("true");
  });

  it("notifica listeners inscritos quando o valor muda", () => {
    const listener = vi.fn();
    const unsubscribe = subscribeSidebarCollapsed(listener);

    setSidebarCollapsed(true);
    expect(listener).toHaveBeenCalledTimes(1);

    unsubscribe();
    setSidebarCollapsed(false);
    expect(listener).toHaveBeenCalledTimes(1); // não chamado depois de cancelar a inscrição
  });
});
