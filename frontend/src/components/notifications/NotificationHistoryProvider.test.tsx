import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  NotificationHistoryProvider,
  useNotificationHistory,
} from "./NotificationHistoryProvider";

function Probe() {
  const { items, unreadCount, push, markAllRead } = useNotificationHistory();
  return (
    <div>
      <button onClick={() => push({ title: "Job concluído", tone: "success" })}>push</button>
      <button onClick={markAllRead}>markAllRead</button>
      <p data-testid="unread">{unreadCount}</p>
      <p data-testid="count">{items.length}</p>
    </div>
  );
}

describe("NotificationHistoryProvider", () => {
  it("começa vazio, sem não-lidas", () => {
    render(
      <NotificationHistoryProvider>
        <Probe />
      </NotificationHistoryProvider>,
    );
    expect(screen.getByTestId("count")).toHaveTextContent("0");
    expect(screen.getByTestId("unread")).toHaveTextContent("0");
  });

  it("push adiciona um item não lido; markAllRead zera o contador sem remover itens", async () => {
    const user = userEvent.setup();
    render(
      <NotificationHistoryProvider>
        <Probe />
      </NotificationHistoryProvider>,
    );

    await user.click(screen.getByText("push"));
    expect(screen.getByTestId("count")).toHaveTextContent("1");
    expect(screen.getByTestId("unread")).toHaveTextContent("1");

    await user.click(screen.getByText("markAllRead"));
    expect(screen.getByTestId("count")).toHaveTextContent("1");
    expect(screen.getByTestId("unread")).toHaveTextContent("0");
  });

  it("useNotificationHistory fora do provider lança um erro claro", () => {
    // Suprime o console.error esperado do React para um erro de render.
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<Probe />)).toThrow(/useNotificationHistory must be used within/);
    spy.mockRestore();
  });
});
