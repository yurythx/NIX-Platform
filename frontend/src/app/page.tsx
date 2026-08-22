import Link from "next/link";

import { Button } from "@/components/ui/Button";

export default function LandingPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 p-6 text-center">
      <div>
        <h1 className="text-3xl font-semibold text-foreground">NIX Platform</h1>
        <p className="mt-2 max-w-md text-muted">
          A corporate modular platform centralizing integrations, automation and notifications
          behind a single extensible dashboard.
        </p>
      </div>
      <Link href="/dashboard">
        <Button size="md">Go to dashboard</Button>
      </Link>
    </div>
  );
}
