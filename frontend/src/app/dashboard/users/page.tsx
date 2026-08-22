"use client";

import { useCallback, useEffect, useState } from "react";

import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorState } from "@/components/ui/ErrorState";
import { Skeleton } from "@/components/ui/Skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeaderCell,
  TableRow,
} from "@/components/ui/Table";
import { apiClient, ApiError } from "@/lib/api/client";
import type { PaginationMeta, User } from "@/types/api";

const PAGE_SIZE = 20;

export default function UsersPage() {
  const [page, setPage] = useState(1);
  const [users, setUsers] = useState<User[] | null>(null);
  const [meta, setMeta] = useState<PaginationMeta | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Nenhum reset síncrono antes da requisição: a tabela da página
  // anterior continua na tela (stale-while-revalidate) até a nova página
  // carregar, em vez de piscar de volta para um skeleton a cada clique.
  const load = useCallback(() => {
    apiClient
      .get<User[]>(`v1/users?page=${page}&page_size=${PAGE_SIZE}`)
      .then(({ data, meta }) => {
        setError(null);
        setUsers(data);
        setMeta((meta as PaginationMeta) ?? null);
      })
      .catch((err: unknown) =>
        setError(err instanceof ApiError ? err.message : "Falha ao carregar usuários"),
      );
  }, [page]);

  useEffect(load, [load]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Usuários</h1>
        <p className="text-sm text-muted">Todos com acesso ao NIX Platform.</p>
      </div>

      {error && <ErrorState message={error} onRetry={load} />}

      {!error && !users && (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      )}

      {!error && users && users.length === 0 && (
        <EmptyState
          title="Ainda não há usuários"
          description="Usuários aparecem aqui assim que fizerem login pela primeira vez."
        />
      )}

      {!error && users && users.length > 0 && (
        <>
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>Nome</TableHeaderCell>
                <TableHeaderCell>Email</TableHeaderCell>
                <TableHeaderCell>Status</TableHeaderCell>
                <TableHeaderCell>Visto por último</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>{user.display_name || user.username}</TableCell>
                  <TableCell>{user.email}</TableCell>
                  <TableCell>{user.active ? "Ativo" : "Inativo"}</TableCell>
                  <TableCell>
                    {user.last_seen_at ? new Date(user.last_seen_at).toLocaleString() : "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {meta && meta.total_pages > 1 && (
            <div className="flex items-center justify-between text-sm text-muted">
              <span>
                Página {meta.page} de {meta.total_pages} ({meta.total_items} usuários)
              </span>
              <div className="flex gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  Anterior
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={page >= meta.total_pages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Próxima
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
