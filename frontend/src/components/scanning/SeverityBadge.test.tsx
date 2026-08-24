import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SeverityBadge } from "./SeverityBadge";

describe("SeverityBadge", () => {
  it.each(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const)(
    "renderiza a severidade %s como texto (não só cor)",
    (severity) => {
      render(<SeverityBadge severity={severity} />);
      expect(screen.getByText(severity)).toBeInTheDocument();
    },
  );

  it("distingue CRITICAL de HIGH pelo texto, já que os dois dividem o mesmo tom de cor", () => {
    const { rerender } = render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();

    rerender(<SeverityBadge severity="HIGH" />);
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    expect(screen.queryByText("CRITICAL")).not.toBeInTheDocument();
  });
});
