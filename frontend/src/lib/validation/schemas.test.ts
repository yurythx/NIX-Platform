import { describe, expect, it } from "vitest";

import {
  integrationStatusPayloadSchema,
  jobEventPayloadSchema,
  parseEventEnvelope,
} from "./schemas";

describe("parseEventEnvelope", () => {
  it("accepts a well-formed envelope", () => {
    const raw = JSON.stringify({
      id: "11111111-1111-1111-1111-111111111111",
      type: "diario_oficial.job.completed",
      version: 1,
      source: "nix.diario_oficial",
      occurred_at: "2026-08-22T00:00:00Z",
      correlation_id: "22222222-2222-2222-2222-222222222222",
      payload: { job_id: "33333333-3333-3333-3333-333333333333" },
    });

    const parsed = parseEventEnvelope(raw);
    expect(parsed).not.toBeNull();
    expect(parsed?.type).toBe("diario_oficial.job.completed");
  });

  it("rejects invalid JSON", () => {
    expect(parseEventEnvelope("not json")).toBeNull();
  });

  it("rejects JSON missing required fields", () => {
    expect(parseEventEnvelope(JSON.stringify({ type: "x" }))).toBeNull();
  });

  it("rejects a JSON array instead of an object", () => {
    expect(parseEventEnvelope(JSON.stringify([1, 2, 3]))).toBeNull();
  });
});

describe("jobEventPayloadSchema", () => {
  it("accepts a payload with job_id", () => {
    const result = jobEventPayloadSchema.safeParse({ job_id: "abc-123" });
    expect(result.success).toBe(true);
  });

  it("rejects a payload missing job_id", () => {
    const result = jobEventPayloadSchema.safeParse({});
    expect(result.success).toBe(false);
  });
});

describe("integrationStatusPayloadSchema", () => {
  it("accepts a known status", () => {
    const result = integrationStatusPayloadSchema.safeParse({
      key: "diario-oficial",
      status: "online",
    });
    expect(result.success).toBe(true);
  });

  it("rejects an unknown status value", () => {
    const result = integrationStatusPayloadSchema.safeParse({
      key: "diario-oficial",
      status: "flying",
    });
    expect(result.success).toBe(false);
  });
});
