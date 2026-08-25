import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { NotificationClient } from "./client";

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closeCalls = 0;

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  close() {
    this.closeCalls += 1;
    this.onclose?.();
  }
}

beforeEach(() => {
  FakeWebSocket.instances = [];
  vi.stubGlobal("WebSocket", FakeWebSocket as unknown as typeof WebSocket);
});

// firstSocket: todo teste abaixo só chama isto depois de um
// vi.waitFor(() => instances tem length 1/2) — a instância sempre
// existe na prática, mas o tipo de array indexado (noUncheckedIndexedAccess)
// não carrega essa garantia. Lança um erro claro em vez de um "possibly
// undefined" silenciado, caso essa invariante um dia deixe de valer.
function firstSocket(): FakeWebSocket {
  const socket = FakeWebSocket.instances[0];
  if (!socket) throw new Error("no FakeWebSocket instance connected yet");
  return socket;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const validEnvelope = JSON.stringify({
  id: "1",
  type: "notification.created",
  version: 1,
  source: "nix.test",
  occurred_at: "2026-08-22T00:00:00Z",
  correlation_id: "corr-1",
  payload: {},
});

describe("NotificationClient", () => {
  it("fetches a ticket and opens a connection with it in the URL", async () => {
    const getTicket = vi.fn().mockResolvedValue("ticket-abc");
    const client = new NotificationClient({
      wsBaseUrl: "ws://localhost:8000/ws",
      getTicket,
      onMessage: vi.fn(),
    });

    client.connect();
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));

    expect(getTicket).toHaveBeenCalledOnce();
    expect(firstSocket().url).toBe("ws://localhost:8000/ws?ticket=ticket-abc");
  });

  it("forwards a well-formed message and drops a malformed one", async () => {
    const onMessage = vi.fn();
    const client = new NotificationClient({
      wsBaseUrl: "ws://localhost:8000/ws",
      getTicket: vi.fn().mockResolvedValue("t"),
      onMessage,
    });

    client.connect();
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    const socket = firstSocket();

    socket.onmessage?.({ data: "not valid json" });
    socket.onmessage?.({ data: validEnvelope });

    expect(onMessage).toHaveBeenCalledOnce();
    expect(onMessage.mock.calls[0]?.[0].type).toBe("notification.created");
  });

  it("reports connection state transitions", async () => {
    const onStateChange = vi.fn();
    const client = new NotificationClient({
      wsBaseUrl: "ws://localhost:8000/ws",
      getTicket: vi.fn().mockResolvedValue("t"),
      onMessage: vi.fn(),
      onStateChange,
    });

    client.connect();
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    expect(onStateChange).toHaveBeenCalledWith("connecting");

    firstSocket().onopen?.();
    expect(onStateChange).toHaveBeenCalledWith("open");
  });

  it("reconnects with backoff after the socket closes, fetching a fresh ticket", async () => {
    vi.useFakeTimers();
    const getTicket = vi.fn().mockResolvedValue("t");
    const backoffMs = vi.fn().mockReturnValue(1000);

    const client = new NotificationClient({
      wsBaseUrl: "ws://localhost:8000/ws",
      getTicket,
      onMessage: vi.fn(),
      backoffMs,
    });

    client.connect();
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    expect(getTicket).toHaveBeenCalledTimes(1);

    firstSocket().onclose?.();

    await vi.advanceTimersByTimeAsync(1000);
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(2));

    expect(getTicket).toHaveBeenCalledTimes(2);
    expect(backoffMs).toHaveBeenCalledWith(0);
  });

  it("does not reconnect after disconnect() is called", async () => {
    vi.useFakeTimers();
    const getTicket = vi.fn().mockResolvedValue("t");

    const client = new NotificationClient({
      wsBaseUrl: "ws://localhost:8000/ws",
      getTicket,
      onMessage: vi.fn(),
    });

    client.connect();
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));

    client.disconnect();
    expect(firstSocket().closeCalls).toBe(1);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });
});
