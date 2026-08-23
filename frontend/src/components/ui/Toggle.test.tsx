import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { Toggle } from "./Toggle";

describe("Toggle", () => {
  it("reflete o estado checked em aria-checked", () => {
    const { rerender } = render(<Toggle checked={false} onChange={() => {}} label="Ativar X" />);
    expect(screen.getByRole("switch", { name: "Ativar X" })).toHaveAttribute("aria-checked", "false");

    rerender(<Toggle checked={true} onChange={() => {}} label="Ativar X" />);
    expect(screen.getByRole("switch", { name: "Ativar X" })).toHaveAttribute("aria-checked", "true");
  });

  it("chama onChange com o valor invertido ao clicar", async () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} label="Ativar X" />);

    await userEvent.click(screen.getByRole("switch", { name: "Ativar X" }));

    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("não chama onChange quando desabilitado", async () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} label="Ativar X" disabled />);

    await userEvent.click(screen.getByRole("switch", { name: "Ativar X" }));

    expect(onChange).not.toHaveBeenCalled();
  });
});
