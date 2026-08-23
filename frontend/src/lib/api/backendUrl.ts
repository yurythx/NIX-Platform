// Endereço interno do backend Go, usado por todo caminho server-side que
// fala com ele diretamente: o proxy BFF (app/api/backend/[...path]/route.ts)
// e a busca de dados em Server Component (lib/api/server.ts) — extraído
// pra um só lugar pra essas duas cadeias de fallback nunca poderem
// divergir uma da outra.
export const BACKEND_INTERNAL_URL =
  process.env.BACKEND_INTERNAL_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
