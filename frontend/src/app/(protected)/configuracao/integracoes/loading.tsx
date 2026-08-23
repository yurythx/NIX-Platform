import { Skeleton } from "@/components/ui/Skeleton";

export default function Loading() {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <Skeleton className="h-40 w-full" />
      <Skeleton className="h-40 w-full" />
    </div>
  );
}
