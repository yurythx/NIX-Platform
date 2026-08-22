import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import type { ReactNode } from "react";

import { DashboardShell } from "@/components/layout/DashboardShell";
import { authOptions } from "@/lib/auth/options";

// Defense in depth: proxy.ts already redirects unauthenticated visitors
// away from /dashboard/**, but a layout-level check means this route
// group is never rendered without a valid session even if proxy
// matching is ever misconfigured.
export default async function DashboardLayout({ children }: { children: ReactNode }) {
  const session = await getServerSession(authOptions);
  if (!session || session.error) {
    redirect("/login");
  }

  const userLabel = session.user?.email ?? session.user?.name ?? "Autenticado";

  return <DashboardShell userLabel={userLabel}>{children}</DashboardShell>;
}
