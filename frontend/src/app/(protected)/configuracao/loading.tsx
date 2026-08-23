import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";

// Cobre só o conteúdo da aba "Sistema" (page.tsx) — as abas em si vêm de
// layout.tsx, que não suspende, então continuam visíveis enquanto isto
// aparece por baixo.
export default function Loading() {
  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-5 w-32" />
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </CardContent>
    </Card>
  );
}
