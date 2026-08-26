import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { NotificationHistoryProvider, useNotificationHistory } from "./NotificationHistoryProvider";
import { NotificationBell } from "./NotificationBell";

// Seeder: empurra itens pro NotificationHistoryProvider real antes do
// teste interagir com o sino — mesmo princípio do Probe em
// NotificationHistoryProvider.test.tsx, só que aqui alimentando
// NotificationBell em vez de inspecionar o contexto diretamente.
function Seed({
  items,
}: {
  items: { title: string; description?: string; tone: "info" | "success" | "danger" }[];
}) {
  const { push } = useNotificationHistory();
  return (
    <button data-testid="seed" onClick={() => items.forEach((i) => push(i))}>
      seed
    </button>
  );
}

function renderBell(
  items: { title: string; description?: string; tone: "info" | "success" | "danger" }[] = [],
) {
  return render(
    <NotificationHistoryProvider>
      <Seed items={items} />
      <NotificationBell />
    </NotificationHistoryProvider>,
  );
}

describe("NotificationBell", () => {
  it("sem notificação nenhuma, não mostra o selo de contagem", () => {
    renderBell();
    expect(screen.getByRole("button", { name: "Notificações" })).toBeInTheDocument();
  });

  it("com notificações não lidas, o aria-label e o selo mostram a contagem", async () => {
    const user = userEvent.setup();
    renderBell([
      { title: "a", tone: "info" },
      { title: "b", tone: "success" },
    ]);
    await user.click(screen.getByTestId("seed"));

    expect(screen.getByRole("button", { name: "Notificações, 2 não lidas" })).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("mais de 9 não lidas mostra '9+' em vez do número exato", async () => {
    const user = userEvent.setup();
    const items = Array.from({ length: 10 }, (_, i) => ({
      title: `item ${i}`,
      tone: "info" as const,
    }));
    renderBell(items);
    await user.click(screen.getByTestId("seed"));

    expect(screen.getByText("9+")).toBeInTheDocument();
  });

  it("abrir o sino lista as notificações e marca tudo como lido (selo some)", async () => {
    const user = userEvent.setup();
    renderBell([{ title: "Scan concluído", description: "3 achados", tone: "info" }]);
    await user.click(screen.getByTestId("seed"));
    expect(screen.getByRole("button", { name: /não lidas/ })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Notificações/ }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    expect(screen.getByText("Scan concluído")).toBeInTheDocument();
    expect(screen.getByText("3 achados")).toBeInTheDocument();

    // markAllRead disparado ao abrir — o aria-label volta a "Notificações"
    // sem o sufixo de contagem, mesmo com os itens ainda na lista.
    expect(screen.getByRole("button", { name: "Notificações" })).toBeInTheDocument();
  });

  it("sem notificação nenhuma, o dropdown mostra o estado vazio", async () => {
    const user = userEvent.setup();
    renderBell();
    await user.click(screen.getByRole("button", { name: "Notificações" }));
    expect(screen.getByText("Nenhuma notificação ainda.")).toBeInTheDocument();
  });

  it("Escape fecha o dropdown aberto", async () => {
    const user = userEvent.setup();
    renderBell();
    await user.click(screen.getByRole("button", { name: "Notificações" }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });
});
