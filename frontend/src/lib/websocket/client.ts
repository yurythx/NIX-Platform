import { parseEventEnvelope, type EventEnvelope } from "@/lib/validation/schemas";

export type ConnectionState = "idle" | "connecting" | "open" | "closed";

interface NotificationClientOptions {
  /** Fetches a fresh short-lived ticket (§38) — called on connect and on
   * every reconnect, since tickets are single-use. */
  getTicket: () => Promise<string>;
  wsBaseUrl: string;
  onMessage: (event: EventEnvelope) => void;
  onStateChange?: (state: ConnectionState) => void;
  /** Overridable for tests; defaults to real exponential backoff. */
  backoffMs?: (attempt: number) => number;
}

const MAX_BACKOFF_MS = 30_000;

function defaultBackoff(attempt: number): number {
  return Math.min(1000 * 2 ** attempt, MAX_BACKOFF_MS);
}

/**
 * Manages one logical WebSocket connection to the platform's notification
 * endpoint: fetches a fresh ticket on every (re)connect, and reconnects
 * with bounded exponential backoff on any close/error — never an
 * aggressive tight retry loop (§39).
 */
export class NotificationClient {
  private socket: WebSocket | null = null;
  private attempt = 0;
  private stopped = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly opts: NotificationClientOptions) {}

  connect(): void {
    this.stopped = false;
    void this.open();
  }

  disconnect(): void {
    this.stopped = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.socket?.close(1000, "client disconnect");
    this.socket = null;
  }

  private async open(): Promise<void> {
    if (this.stopped) return;
    this.setState("connecting");

    let ticket: string;
    try {
      ticket = await this.opts.getTicket();
    } catch {
      this.scheduleReconnect();
      return;
    }
    if (this.stopped) return;

    const url = `${this.opts.wsBaseUrl}?ticket=${encodeURIComponent(ticket)}`;
    const socket = new WebSocket(url);
    this.socket = socket;

    socket.onopen = () => {
      this.attempt = 0;
      this.setState("open");
    };

    socket.onmessage = (ev) => {
      const parsed = parseEventEnvelope(typeof ev.data === "string" ? ev.data : "");
      if (!parsed) {
        console.warn("nix-platform: dropped malformed WebSocket message");
        return;
      }
      this.opts.onMessage(parsed);
    };

    socket.onclose = () => {
      this.setState("closed");
      if (!this.stopped) this.scheduleReconnect();
    };

    socket.onerror = () => {
      // onclose fires right after onerror for browser WebSockets; the
      // reconnect is scheduled there to avoid double-scheduling.
      socket.close();
    };
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    const backoff = (this.opts.backoffMs ?? defaultBackoff)(this.attempt);
    this.attempt += 1;
    this.reconnectTimer = setTimeout(() => void this.open(), backoff);
  }

  private setState(state: ConnectionState): void {
    this.opts.onStateChange?.(state);
  }
}
