import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { ThemeToggle } from "./ThemeToggle";

function clearThemeCookie() {
  document.cookie = "nix-theme=; path=/; max-age=0";
}

describe("ThemeToggle", () => {
  afterEach(() => {
    clearThemeCookie();
    document.documentElement.removeAttribute("data-theme");
  });

  it("sem initialTheme, mostra o rótulo para ativar o tema escuro (assume claro)", () => {
    render(<ThemeToggle />);
    expect(screen.getByRole("button", { name: "Ativar tema escuro" })).toBeInTheDocument();
  });

  it("com initialTheme='dark', mostra o rótulo para voltar ao tema claro", () => {
    render(<ThemeToggle initialTheme="dark" />);
    expect(screen.getByRole("button", { name: "Ativar tema claro" })).toBeInTheDocument();
  });

  it("ao clicar, grava o cookie nix-theme e atualiza data-theme em <html>", async () => {
    const user = userEvent.setup();
    render(<ThemeToggle initialTheme="light" />);

    await user.click(screen.getByRole("button", { name: "Ativar tema escuro" }));

    expect(document.cookie).toContain("nix-theme=dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(screen.getByRole("button", { name: "Ativar tema claro" })).toBeInTheDocument();
  });
});
