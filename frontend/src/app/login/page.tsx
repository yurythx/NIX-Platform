import { connection } from "next/server";
import { Suspense } from "react";

import { LoginCard } from "@/components/auth/LoginCard";

export default async function LoginPage() {
  // Força renderização dinâmica — necessário para que o
  // Content-Security-Policy com nonce (proxy.ts) seja aplicado
  // corretamente; veja o comentário equivalente em app/page.tsx.
  await connection();

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <Suspense fallback={null}>
        <LoginCard />
      </Suspense>
    </div>
  );
}
