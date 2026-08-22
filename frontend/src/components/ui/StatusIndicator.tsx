import type { IntegrationStatus } from "@/types/api";

// Um ponto colorido + rótulo em texto — deliberadamente não um emoji (§42)
// — com o status também disponível como texto para leitores de tela e
// pessoas com daltonismo, que nunca poderiam distinguir só pela cor.
const statusLabel: Record<IntegrationStatus, string> = {
  online: "Online",
  offline: "Offline",
  degraded: "Degradado",
  disabled: "Desabilitado",
  unknown: "Desconhecido",
};

// Classes Tailwind (não style="" inline!) geradas a partir dos tokens
// --color-status-* declarados em globals.css. Um atributo style inline
// seria bloqueado pela Content-Security-Policy baseada em nonce definida
// em proxy.ts — nonce só libera tags <script>/<style>, nunca atributos
// style="" em elementos quaisquer.
const statusDotClass: Record<IntegrationStatus, string> = {
  online: "bg-status-online",
  offline: "bg-status-offline",
  degraded: "bg-status-degraded",
  disabled: "bg-status-disabled",
  unknown: "bg-status-unknown",
};

export function StatusIndicator({ status }: { status: IntegrationStatus }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span className={`h-2 w-2 rounded-full ${statusDotClass[status]}`} aria-hidden="true" />
      <span>{statusLabel[status]}</span>
    </span>
  );
}
