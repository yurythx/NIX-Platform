import type { IntegrationStatus } from "@/types/api";

// A colored dot + text label — deliberately not an emoji (§42) — with the
// status also carried in text for screen readers and color-blind users.
const statusLabel: Record<IntegrationStatus, string> = {
  online: "Online",
  offline: "Offline",
  degraded: "Degraded",
  disabled: "Disabled",
  unknown: "Unknown",
};

const statusColorVar: Record<IntegrationStatus, string> = {
  online: "var(--status-online)",
  offline: "var(--status-offline)",
  degraded: "var(--status-degraded)",
  disabled: "var(--status-disabled)",
  unknown: "var(--status-unknown)",
};

export function StatusIndicator({ status }: { status: IntegrationStatus }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span
        className="h-2 w-2 rounded-full"
        style={{ backgroundColor: statusColorVar[status] }}
        aria-hidden="true"
      />
      <span>{statusLabel[status]}</span>
    </span>
  );
}
