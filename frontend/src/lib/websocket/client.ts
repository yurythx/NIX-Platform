import { parseEventEnvelope, type EventEnvelope } from "@/lib/validation/schemas";

export type ConnectionState = "idle" | "connecting" | "open" | "closed";

interface NotificationClientOptions {
  /** Busca um ticket novo de curta duração (§38) — chamado ao conectar e
   * em toda reconexão, já que tickets são de uso único. */
  getTicket: () => Promise<string>;
  wsBaseUrl: string;
  onMessage: (event: EventEnvelope) => void;
  onStateChange?: (state: ConnectionState) => void;
  /** Sobrescrevível nos testes; usa o backoff exponencial real por padrão. */
  backoffMs?: (attempt: number) => number;
}

const MAX_BACKOFF_MS = 30_000;

function defaultBackoff(attempt: number): number {
  return Math.min(1000 * 2 ** attempt, MAX_BACKOFF_MS);
}

/**
 * Gerencia uma conexão WebSocket lógica com o endpoint de notificações da
 * plataforma: busca um ticket novo a cada (re)conexão, e reconecta com
 * backoff exponencial limitado em qualquer close/error — nunca um loop de
 * retry agressivo e sem limite (§39), o que sobrecarregaria o backend numa
 * instabilidade prolongada.
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
      // onclose dispara logo depois de onerror em WebSockets de
      // navegador; a reconexão é agendada lá para evitar agendar duas
      // vezes.
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
