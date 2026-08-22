import { z } from "zod";

// Mirrors the backend's standard event envelope (§17). Every message
// received over the WebSocket is validated against this before the
// frontend acts on it (§43) — an unexpected shape is dropped and logged,
// never trusted blindly.
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

export const jobEventPayloadSchema = z.object({
  job_id: z.string(),
});

export const integrationStatusPayloadSchema = z.object({
  key: z.string(),
  status: z.enum(["unknown", "online", "offline", "degraded", "disabled"]),
});

/** Parses and validates a raw WebSocket message; returns null on any
 * malformed input instead of throwing, so one bad message never crashes
 * the notification pipeline. */
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
