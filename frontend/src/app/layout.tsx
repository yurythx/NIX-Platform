import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { cookies } from "next/headers";
import type { ReactNode } from "react";
import "./globals.css";

import { Providers } from "./providers";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "NIX Platform",
  description: "Plataforma corporativa modular — integrações, automação e notificações.",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Lê o cookie "nix-theme" (escrito por components/ui/ThemeToggle.tsx)
  // no servidor e carimba data-theme em <html> ANTES do primeiro paint —
  // zero flash de tema errado, sem precisar de nenhum <script> inline
  // (que a CSP com nonce deste app bloquearia — ver a nota em
  // ThemeToggle.tsx). Sem cookie (primeira visita), nenhum atributo é
  // definido e o CSS puro em globals.css segue prefers-color-scheme.
  const cookieStore = await cookies();
  const theme = cookieStore.get("nix-theme")?.value;
  const dataTheme = theme === "dark" || theme === "light" ? theme : undefined;

  return (
    <html
      lang="pt-BR"
      data-theme={dataTheme}
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
