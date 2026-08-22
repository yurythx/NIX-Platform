"use client";

import { SessionProvider } from "next-auth/react";
import type { ReactNode } from "react";

// Envolve toda a árvore da aplicação com o contexto de sessão do
// NextAuth, para que useSession()/signIn()/signOut() funcionem em
// qualquer Client Component sem cada um precisar buscar a sessão por
// conta própria.
export function Providers({ children }: { children: ReactNode }) {
  return <SessionProvider>{children}</SessionProvider>;
}
