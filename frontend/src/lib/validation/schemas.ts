import { z } from "zod";

// Espelha o envelope de evento padrão do backend (§17). Toda mensagem
// recebida via WebSocket é validada contra este schema antes de o
// frontend agir sobre ela (§43) — um formato inesperado é descartado e
// logado, nunca confiado às cegas (o servidor pode evoluir o payload de
// um jeito que o frontend ainda não conhece, ou a mensagem pode vir
// corrompida).
export const eventEnvelopeSchema = z.object({
  id: z.string(),
  type: z.string(),
  version: z.number(),
  source: z.string(),
  occurred_at: z.string(),
  correlation_id: z.string(),
  payload: z.unknown(),
});

export type EventEnvelope = z.infer<typeof eventEnvelopeSchema>;

// Payload dos eventos do ciclo de vida de um job (diario_oficial.job.*,
// integration.test.completed) — só o id do job, usado para montar a
// mensagem do toast (ver NotificationCenter).
export const jobEventPayloadSchema = z.object({
  job_id: z.string(),
});

// Payload do evento integration.status.changed — a chave da integração e
// seu novo status, usado para o toast "Integração X agora está Y".
export const integrationStatusPayloadSchema = z.object({
  key: z.string(),
  status: z.enum(["unknown", "online", "offline", "degraded", "disabled"]),
});

/** Faz o parse e valida uma mensagem bruta de WebSocket; retorna null para
 * qualquer entrada malformada em vez de lançar exceção, para que uma
 * mensagem ruim nunca derrube o pipeline de notificações inteiro. */
export function parseEventEnvelope(raw: string): EventEnvelope | null {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return null;
  }

  const result = eventEnvelopeSchema.safeParse(json);
  return result.success ? result.data : null;
}
