"use client";

import { useRouter } from "next/navigation";
import { useRef, useState, type FormEvent } from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { useToast } from "@/components/notifications/ToastProvider";
import { apiClient, ApiError } from "@/lib/api/client";
import type { Project } from "@/types/api";

type Tab = "git" | "upload";

// MAX_UPLOAD_ZIP_BYTES espelha application.maxUploadZipBytes no backend
// (scanning/application/service.go) — duplicado aqui só pra dar feedback
// imediato no navegador; o backend continua sendo a validação que
// realmente importa, nunca confiável vinda só do cliente.
const MAX_UPLOAD_ZIP_BYTES = 50 * 1024 * 1024;

// NewProjectForm: Fase 10 (Projeto persistente + upload .zip) — duas
// abas, exatamente como a proposta original pedia (seção 5.A): URL git
// (mesmo formato https://...#branch que um scan avulso já aceita) ou
// upload de um .zip (extraído no worker só na hora de escanear — nunca
// aqui, nunca guardado extraído em disco, ver
// docs/roadmap-secops-orchestrator.md). Depois de criado, o projeto some
// deste formulário e aparece como um card em "Projetos" — refresh via
// router.refresh() (Server Component pai busca a lista de novo), mesmo
// padrão que o resto desta plataforma usa em vez de duplicar estado
// client-side do que o servidor já é dono.
export function NewProjectForm() {
  const router = useRouter();
  const { showToast } = useToast();
  const [tab, setTab] = useState<Tab>("git");
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  function resetForm() {
    setName("");
    setTarget("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;

    setSubmitting(true);
    try {
      if (tab === "git") {
        if (!target.trim()) return;
        await apiClient.post<Project>("v1/scanning/projects", { name: name.trim(), target: target.trim() });
      } else {
        const file = fileInputRef.current?.files?.[0];
        if (!file) {
          showToast({ title: "Selecione um arquivo .zip", tone: "danger" });
          setSubmitting(false);
          return;
        }
        // Mesmo limite do backend (application.maxUploadZipBytes) —
        // checado aqui ANTES de montar o FormData/enviar: achado de
        // auditoria — sem isso, um arquivo grande demais só é rejeitado
        // DEPOIS do upload inteiro terminar (a resposta 422 só chega
        // quando o corpo já foi todo enviado), desperdiçando o tempo/
        // banda do usuário à toa.
        if (file.size > MAX_UPLOAD_ZIP_BYTES) {
          showToast({
            title: "Arquivo .zip muito grande",
            description: `O limite é ${MAX_UPLOAD_ZIP_BYTES / (1024 * 1024)}MB — este arquivo tem ${(file.size / (1024 * 1024)).toFixed(1)}MB.`,
            tone: "danger",
          });
          setSubmitting(false);
          return;
        }
        const form = new FormData();
        form.set("name", name.trim());
        form.set("file", file);
        await apiClient.postForm<Project>("v1/scanning/projects", form);
      }

      showToast({ title: "Projeto criado", description: name.trim(), tone: "info" });
      resetForm();
      router.refresh();
    } catch (err) {
      showToast({
        title: "Não foi possível criar o projeto",
        description: err instanceof ApiError ? err.message : "Erro inesperado",
        tone: "danger",
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Novo projeto</CardTitle>
        <CardDescription>
          Guarde um alvo pra rodar de novo depois sem digitar a URL (ou reanexar o .zip) toda vez.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="mb-4 flex gap-2 border-b border-surface-border">
          {(["git", "upload"] as const).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
                tab === t
                  ? "border-primary text-primary"
                  : "border-transparent text-muted hover:text-foreground"
              }`}
            >
              {t === "git" ? "URL git" : "Upload .zip"}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <Input
            label="Nome"
            name="name"
            placeholder="ex.: api-principal"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />

          {tab === "git" ? (
            <Input
              label="Alvo"
              name="target"
              placeholder="https://github.com/org/repo.git#main"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              required
            />
          ) : (
            <div className="flex flex-col gap-1">
              <label htmlFor="project-zip-file" className="text-sm font-medium text-foreground">
                Arquivo .zip
              </label>
              <input
                ref={fileInputRef}
                id="project-zip-file"
                type="file"
                accept=".zip"
                required
                className="text-sm text-foreground file:mr-3 file:rounded-md file:border file:border-surface-border file:bg-surface file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-foreground hover:file:bg-black/5 dark:hover:file:bg-white/5"
              />
              <p className="text-xs text-muted">
                Um projeto por upload nunca roda SonarQube nem OWASP ZAP — o primeiro exige um
                clone git, o segundo ataca uma URL viva.
              </p>
            </div>
          )}

          <div>
            <Button type="submit" loading={submitting}>
              Criar projeto
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
