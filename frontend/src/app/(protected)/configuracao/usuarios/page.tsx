import Link from "next/link";

import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorState } from "@/components/ui/ErrorState";
import { Section } from "@/components/ui/Section";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeaderCell,
  TableRow,
} from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import { serverApiGet } from "@/lib/api/server";
import type { PaginationMeta, User } from "@/types/api";

const PAGE_SIZE = 20;

// Mesmo visual de Button (variant="secondary" size="sm") — como link de
// navegação real, não um <button> aninhado dentro de <a> (o padrão usado
// em outros lugares desta aplicação para ações de navegação, mas que não
// serve aqui: precisamos expressar "desabilitado" quando não há página
// anterior/seguinte, o que um Link não consegue representar de forma
// limpa).
const pageLinkClass =
  "inline-flex items-center justify-center rounded-md border border-surface-border bg-surface px-3 py-1.5 text-sm font-medium text-foreground transition-colors hover:bg-black/5 dark:hover:bg-white/5";
const pageLinkDisabledClass =
  "inline-flex items-center justify-center rounded-md border border-surface-border px-3 py-1.5 text-sm font-medium text-muted opacity-50";

// Aba "Usuários" de /configuracao. Server Component (§ Migração pra
// Server Components): a paginação vira ?page=N na própria URL em vez de
// useState no cliente — o padrão idiomático do App Router (a página fica
// compartilhável/favoritável numa página específica, e é o que torna esta
// rota buscável no servidor pra começo de conversa: searchParams só
// existe do lado do servidor).
export default async function UsuariosPage({
  searchParams,
}: {
  searchParams: Promise<{ page?: string }>;
}) {
  const { page: pageParam } = await searchParams;
  const page = Math.max(1, Number(pageParam) || 1);

  let users: User[] | null = null;
  let meta: PaginationMeta | null = null;
  let errorMessage: string | null = null;
  try {
    const { data, meta: responseMeta } = await serverApiGet<User[]>(
      `v1/users?page=${page}&page_size=${PAGE_SIZE}`,
    );
    users = data;
    meta = (responseMeta as PaginationMeta) ?? null;
  } catch (err) {
    errorMessage = err instanceof ApiError ? err.message : "Falha ao carregar usuários";
  }

  return (
    <Section title="Usuários" description="Toda conta que já fez login pelo menos uma vez.">
      <div className="flex flex-col gap-4">
        {errorMessage && <ErrorState message={errorMessage} />}

        {!errorMessage && users && users.length === 0 && (
          <EmptyState
            title="Ainda não há usuários"
            description="Usuários aparecem aqui assim que fizerem login pela primeira vez."
          />
        )}

        {users && users.length > 0 && (
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
                  {page > 1 ? (
                    <Link href={`/configuracao/usuarios?page=${page - 1}`} className={pageLinkClass}>
                      Anterior
                    </Link>
                  ) : (
                    <span className={pageLinkDisabledClass} aria-disabled="true">
                      Anterior
                    </span>
                  )}
                  {meta.total_pages > page ? (
                    <Link href={`/configuracao/usuarios?page=${page + 1}`} className={pageLinkClass}>
                      Próxima
                    </Link>
                  ) : (
                    <span className={pageLinkDisabledClass} aria-disabled="true">
                      Próxima
                    </span>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </Section>
  );
}
