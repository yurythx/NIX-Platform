import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";

// Suspense boundary do App Router (§ Migração pra Server Components):
// mostrado automaticamente enquanto page.tsx desta rota busca dados no
// servidor — substitui o skeleton manual que useEffect+useState
// desenhavam antes, sem nenhum código de "carregando" na própria página.
export default function Loading() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="h-4 w-64" />
      </div>
      <div className="flex flex-wrap gap-3">
        <Skeleton className="h-8 w-36" />
        <Skeleton className="h-8 w-44" />
        <Skeleton className="h-8 w-32" />
      </div>
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-40" />
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          <Skeleton className="h-6 w-full" />
          <Skeleton className="h-6 w-full" />
        </CardContent>
      </Card>
    </div>
  );
}
