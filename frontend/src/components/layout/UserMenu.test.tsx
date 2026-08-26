import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

const { signOut } = vi.hoisted(() => ({ signOut: vi.fn().mockResolvedValue(undefined) }));
vi.mock("next-auth/react", () => ({ signOut }));

import { UserMenu } from "./UserMenu";

function mockLogoutUrlFetch(url: string) {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ json: async () => ({ url }) }));
}

describe("UserMenu", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    signOut.mockClear();
    // @ts-expect-error jsdom não implementa navegação real — cada teste
    // que dispara fullSignOut() reatribui window.location.href, o que
    // jsdom aceita silenciosamente sem navegar de fato.
    delete window.location;
    // @ts-expect-error idem — devolve um objeto simples o bastante pra
    // "window.location.href = ..." não lançar entre os testes.
    window.location = {};
  });

  it("mostra as iniciais derivadas do label (duas palavras)", () => {
    render(<UserMenu userLabel="ana.silva" />);
    expect(screen.getByRole("button", { name: /Menu do usuário ana.silva/ })).toHaveTextContent(
      "AS",
    );
  });

  it("com um e-mail, usa a parte antes do @ pra derivar as iniciais", () => {
    render(<UserMenu userLabel="ana.silva@nix.local" />);
    expect(screen.getByRole("button", { name: /Menu do usuário/ })).toHaveTextContent("AS");
  });

  it("com um label de uma palavra só, usa a primeira letra", () => {
    render(<UserMenu userLabel="admin" />);
    expect(screen.getByRole("button", { name: /Menu do usuário/ })).toHaveTextContent("A");
  });

  it("clicar no avatar abre o menu com o label completo e o botão Sair", async () => {
    const user = userEvent.setup();
    render(<UserMenu userLabel="admin@nix.local" />);

    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Menu do usuário/ }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    expect(screen.getByText("admin@nix.local")).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Sair" })).toBeInTheDocument();
  });

  it("Escape fecha o menu aberto", async () => {
    const user = userEvent.setup();
    render(<UserMenu userLabel="admin" />);

    await user.click(screen.getByRole("button", { name: /Menu do usuário/ }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("clicar fora do menu aberto fecha ele", async () => {
    const user = userEvent.setup();
    render(
      <div>
        <UserMenu userLabel="admin" />
        <button>fora</button>
      </div>,
    );

    await user.click(screen.getByRole("button", { name: /Menu do usuário/ }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await user.click(screen.getByText("fora"));
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  // Logout completo (RP-Initiated Logout — §30): busca a URL de logout
  // do Keycloak ENQUANTO a sessão local ainda existe, só então limpa a
  // sessão local (signOut), e só então navega até essa URL — nunca a
  // ordem inversa, que deixaria a sessão viva no Keycloak.
  it("Sair busca a URL de logout do Keycloak, encerra a sessão local e navega até ela", async () => {
    mockLogoutUrlFetch("https://keycloak.example.com/realms/nix/protocol/openid-connect/logout");
    const user = userEvent.setup();
    render(<UserMenu userLabel="admin" />);

    await user.click(screen.getByRole("button", { name: /Menu do usuário/ }));
    await user.click(screen.getByRole("menuitem", { name: "Sair" }));

    expect(fetch).toHaveBeenCalledWith("/api/auth/keycloak-logout-url");
    expect(signOut).toHaveBeenCalledWith({ redirect: false });
    expect(window.location.href).toBe(
      "https://keycloak.example.com/realms/nix/protocol/openid-connect/logout",
    );
  });

  it("se a busca da URL de logout falhar, ainda assim completa o logout local (fallback pra '/')", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network error")));
    const user = userEvent.setup();
    render(<UserMenu userLabel="admin" />);

    await user.click(screen.getByRole("button", { name: /Menu do usuário/ }));
    await user.click(screen.getByRole("menuitem", { name: "Sair" }));

    expect(signOut).toHaveBeenCalledWith({ redirect: false });
    expect(window.location.href).toBe("/");
  });
});
