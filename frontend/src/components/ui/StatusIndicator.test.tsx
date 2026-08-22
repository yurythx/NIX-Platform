import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StatusIndicator } from "./StatusIndicator";

describe("StatusIndicator", () => {
  it.each([
    ["online", "Online"],
    ["offline", "Offline"],
    ["degraded", "Degradado"],
    ["disabled", "Desabilitado"],
    ["unknown", "Desconhecido"],
  ] as const)("renderiza o status %s como texto %s (não só cor)", (status, label) => {
    render(<StatusIndicator status={status} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
});
