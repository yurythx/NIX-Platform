import { FeatureFlagsPanel } from "@/components/settings/FeatureFlagsPanel";

// Aba "Sistema" (índice de /configuracao) — configuração dinâmica via
// feature flags. O endpoint (GET/PATCH /api/v1/admin/feature-flags) já
// existia desde o upgrade enterprise; esta é a primeira UI pra ele.
export default function SistemaPage() {
  return <FeatureFlagsPanel />;
}
