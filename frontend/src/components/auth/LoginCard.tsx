"use client";

import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";

// Extraído de app/login/page.tsx como Client Component separado porque
// useSearchParams()/signIn() exigem "use client", enquanto a própria
// página de login precisa ser um Server Component assíncrono (chama
// `await connection()`) para habilitar renderização dinâmica — sem isso o
// nonce do CSP gerado em proxy.ts nunca bateria com o nonce embutido no
// HTML estático (ver a nota de bug em proxy.ts/app/login/page.tsx).
//
// Dois caminhos de login lado a lado (§ Sistema de Login Local): o botão
// do Keycloak (o principal, Authorization Code + PKCE via NextAuth) e um
// formulário de usuário/senha que autentica contra o provider
// "local" — ver lib/auth/options.ts. Os dois produzem o mesmo tipo de
// sessão NextAuth no final; o resto da aplicação não precisa saber qual
// caminho o usuário usou.
export function LoginCard() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/dashboard";
  const oauthError = searchParams.get("error");

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleLocalLogin(e: FormEvent) {
    e.preventDefault();
    setLocalError(null);
    setSubmitting(true);
    try {
      const result = await signIn("local", { username, password, redirect: false });
      if (!result || result.error) {
        setLocalError("Usuário ou senha inválidos.");
        return;
      }
      router.push(callbackUrl);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>Entrar no NIX Platform</CardTitle>
        <CardDescription>Use o Keycloak da sua organização ou um usuário local.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {oauthError && (
          <p role="alert" className="text-sm text-danger">
            Falha ao entrar. Tente novamente.
          </p>
        )}

        <Button className="w-full" onClick={() => signIn("keycloak", { callbackUrl })}>
          Entrar com Keycloak
        </Button>

        <div className="flex items-center gap-3 text-xs text-muted" aria-hidden="true">
          <div className="h-px flex-1 bg-surface-border" />
          ou
          <div className="h-px flex-1 bg-surface-border" />
        </div>

        <form className="flex flex-col gap-3" onSubmit={handleLocalLogin}>
          <Input
            label="Usuário"
            name="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
          <Input
            label="Senha"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            error={localError ?? undefined}
          />
          <Button type="submit" variant="secondary" className="w-full" loading={submitting}>
            Entrar com usuário local
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
