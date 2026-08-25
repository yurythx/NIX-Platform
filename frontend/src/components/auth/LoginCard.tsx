"use client";

import { Eye, EyeOff } from "lucide-react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";

// Extraído de app/login/page.tsx como Client Component separado porque
// useSearchParams()/signIn() exigem "use client", enquanto a própria
// página de login precisa ser um Server Component assíncrono (chama
// `await connection()`) para habilitar renderização dinâmica — sem isso o
// nonce do CSP gerado em proxy.ts nunca bateria com o nonce embutido no
// HTML estático (ver a nota de bug em proxy.ts/app/login/page.tsx).
//
// Dois caminhos de login (§ Sistema de Login Local): o formulário
// usuário/senha, tratado aqui como o caminho PRINCIPAL — o padrão mais
// familiar, sem nenhuma rotulagem de "conta local" — e o SSO corporativo
// (Keycloak, Authorization Code + PKCE via NextAuth) como alternativa
// secundária abaixo do divisor. Os dois produzem o mesmo tipo de sessão
// NextAuth no final; o resto da aplicação não precisa saber qual caminho
// o usuário usou.
//
// Sem um Card com borda/sombra em volta (ao contrário da versão
// anterior): o painel direito de app/login/page.tsx já é o "container"
// visual (§ Redesenho do login, inspirado em papermoon.cloud) — outra
// caixa por dentro dele ficaria redundante.
export function LoginCard() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/dashboard";
  const oauthError = searchParams.get("error");

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleLogin(e: FormEvent) {
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
    <div className="flex w-full max-w-sm flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Bem-vindo de volta</h1>
        <p className="mt-1 text-sm text-muted">Informe seu usuário e senha para continuar.</p>
      </div>

      {oauthError && (
        <p role="alert" className="text-sm text-danger">
          Falha ao entrar. Tente novamente.
        </p>
      )}

      <form className="flex flex-col gap-3" onSubmit={handleLogin}>
        <Input
          label="Usuário"
          name="username"
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <div className="relative">
          <Input
            label="Senha"
            name="password"
            type={showPassword ? "text" : "password"}
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            error={localError ?? undefined}
            className="pr-10"
          />
          {/* h-10 w-10 com o ícone centralizado por flex (não só o ícone de
              16px sozinho, sem padding) — § revisão de mobile 2026-08: um
              alvo de toque de ~16px fica bem abaixo do mínimo recomendado
              (24px, WCAG 2.5.5 AA). right-0/top-6 alinham essa caixa maior
              com a caixa do <input> em si (pula só a altura do label
              "Senha" acima) — pr-10 no Input reserva exatamente esse
              espaço, então a caixa clicável não invade o texto digitado. */}
          <button
            type="button"
            onClick={() => setShowPassword((v) => !v)}
            aria-label={showPassword ? "Ocultar senha" : "Mostrar senha"}
            aria-pressed={showPassword}
            className="absolute right-0 top-6 flex h-10 w-10 items-center justify-center text-muted hover:text-foreground"
          >
            {showPassword ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
          </button>
        </div>
        <Button type="submit" className="w-full" loading={submitting}>
          Entrar
        </Button>
      </form>

      <div className="flex items-center gap-3 text-xs text-muted" aria-hidden="true">
        <div className="h-px flex-1 bg-surface-border" />
        ou
        <div className="h-px flex-1 bg-surface-border" />
      </div>

      <Button variant="secondary" className="w-full" onClick={() => signIn("keycloak", { callbackUrl })}>
        Entrar com SSO corporativo
      </Button>
    </div>
  );
}
