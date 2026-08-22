"use client";

import { signIn } from "next-auth/react";
import { useSearchParams } from "next/navigation";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";

export function LoginCard() {
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/dashboard";
  const error = searchParams.get("error");

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>Entrar no NIX Platform</CardTitle>
        <CardDescription>A autenticação é feita pelo Keycloak da sua organização.</CardDescription>
      </CardHeader>
      <CardContent>
        {error && (
          <p role="alert" className="mb-4 text-sm text-danger">
            Falha ao entrar. Tente novamente.
          </p>
        )}
        <Button className="w-full" onClick={() => signIn("keycloak", { callbackUrl })}>
          Entrar com Keycloak
        </Button>
      </CardContent>
    </Card>
  );
}
