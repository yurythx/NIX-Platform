"use client";

import { signIn } from "next-auth/react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";

function LoginCard() {
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/dashboard";
  const error = searchParams.get("error");

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>Sign in to NIX Platform</CardTitle>
        <CardDescription>
          Authentication is handled by your organization&apos;s Keycloak.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {error && (
          <p role="alert" className="mb-4 text-sm text-danger">
            Sign-in failed. Please try again.
          </p>
        )}
        <Button className="w-full" onClick={() => signIn("keycloak", { callbackUrl })}>
          Sign in with Keycloak
        </Button>
      </CardContent>
    </Card>
  );
}

export default function LoginPage() {
  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <Suspense fallback={null}>
        <LoginCard />
      </Suspense>
    </div>
  );
}
