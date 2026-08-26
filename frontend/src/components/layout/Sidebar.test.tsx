import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

// Sidebar lê a rota atual via usePathname() pra marcar o link ativo —
// mesmo padrão de mock já usado em NewProjectForm.test.tsx pra
// next/navigation.
const { usePathname } = vi.hoisted(() => ({ usePathname: vi.fn() }));
vi.mock("next/navigation", () => ({ usePathname }));

import { Sidebar } from "./Sidebar";

describe("Sidebar", () => {
  it("marca só o link exato como ativo em /dashboard (sem sub-rotas próprias)", () => {
    usePathname.mockReturnValue("/dashboard");
    render(<Sidebar collapsed={false} mobileOpen={false} onCloseMobile={() => {}} />);
    expect(screen.getByRole("link", { name: /Visão geral/ })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByRole("link", { name: /Integrações/ })).not.toHaveAttribute("aria-current");
  });

  it("marca o link ativo também numa sub-rota (startsWith)", () => {
    usePathname.mockReturnValue("/configuracao/usuarios");
    render(<Sidebar collapsed={false} mobileOpen={false} onCloseMobile={() => {}} />);
    expect(screen.getByRole("link", { name: /Configurações/ })).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  it("clicar num link fecha o painel mobile (onCloseMobile)", async () => {
    usePathname.mockReturnValue("/dashboard");
    const user = userEvent.setup();
    const onCloseMobile = vi.fn();
    render(<Sidebar collapsed={false} mobileOpen onCloseMobile={onCloseMobile} />);

    await user.click(screen.getByRole("link", { name: /Integrações/ }));
    expect(onCloseMobile).toHaveBeenCalled();
  });

  it("Escape fecha o painel mobile só quando ele está aberto", async () => {
    usePathname.mockReturnValue("/dashboard");
    const user = userEvent.setup();
    const onCloseMobile = vi.fn();
    const { rerender } = render(
      <Sidebar collapsed={false} mobileOpen={false} onCloseMobile={onCloseMobile} />,
    );

    await user.keyboard("{Escape}");
    expect(onCloseMobile).not.toHaveBeenCalled();

    rerender(<Sidebar collapsed={false} mobileOpen onCloseMobile={onCloseMobile} />);
    await user.keyboard("{Escape}");
    expect(onCloseMobile).toHaveBeenCalled();
  });

  it("clicar no overlay do painel mobile fecha o painel", async () => {
    usePathname.mockReturnValue("/dashboard");
    const user = userEvent.setup();
    const onCloseMobile = vi.fn();
    const { container } = render(
      <Sidebar collapsed={false} mobileOpen onCloseMobile={onCloseMobile} />,
    );

    const overlay = container.querySelector('[aria-hidden="true"].fixed');
    expect(overlay).not.toBeNull();
    await user.click(overlay as Element);
    expect(onCloseMobile).toHaveBeenCalled();
  });
});
