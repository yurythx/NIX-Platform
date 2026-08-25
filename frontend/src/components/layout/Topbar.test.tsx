import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

// NotificationBell/ThemeToggle/UserMenu têm sua própria lógica (e seus
// próprios testes) — mockados aqui como stubs pra isolar só o que é
// genuinamente do Topbar: o botão de alternar a Sidebar e o indicador de
// status da conexão WebSocket.
vi.mock("@/components/notifications/NotificationBell", () => ({
  NotificationBell: () => <div data-testid="notification-bell-stub" />,
}));
vi.mock("@/components/ui/ThemeToggle", () => ({
  ThemeToggle: () => <div data-testid="theme-toggle-stub" />,
}));
vi.mock("@/components/layout/UserMenu", () => ({
  UserMenu: ({ userLabel }: { userLabel: string }) => (
    <div data-testid="user-menu-stub">{userLabel}</div>
  ),
}));

import { Topbar } from "./Topbar";

describe("Topbar", () => {
  it("clicar no botão de menu chama onToggleSidebar", async () => {
    const user = userEvent.setup();
    const onToggleSidebar = vi.fn();
    render(<Topbar userLabel="admin" connectionState="open" onToggleSidebar={onToggleSidebar} />);

    await user.click(screen.getByRole("button", { name: "Alternar menu lateral" }));
    expect(onToggleSidebar).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["idle", "Conectando…"],
    ["connecting", "Conectando…"],
    ["open", "Ao vivo"],
    ["closed", "Reconectando…"],
  ] as const)("estado da conexão %s mostra o rótulo '%s'", (state, label) => {
    render(<Topbar userLabel="admin" connectionState={state} onToggleSidebar={() => {}} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("repassa userLabel pro UserMenu", () => {
    render(<Topbar userLabel="ana@nix.local" connectionState="open" onToggleSidebar={() => {}} />);
    expect(screen.getByTestId("user-menu-stub")).toHaveTextContent("ana@nix.local");
  });
});
