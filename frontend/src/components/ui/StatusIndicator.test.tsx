import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StatusIndicator } from "./StatusIndicator";

describe("StatusIndicator", () => {
  it.each([
    ["online", "Online"],
    ["offline", "Offline"],
    ["degraded", "Degraded"],
    ["disabled", "Disabled"],
    ["unknown", "Unknown"],
  ] as const)("renders the %s status as text %s (not just color)", (status, label) => {
    render(<StatusIndicator status={status} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
});
