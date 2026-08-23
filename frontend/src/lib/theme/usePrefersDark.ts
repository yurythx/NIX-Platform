"use client";

import { useSyncExternalStore } from "react";

// Assina window.matchMedia("(prefers-color-scheme: dark)") via
// useSyncExternalStore em vez de useState+useEffect — a primitiva que o
// próprio React recomenda para "estado que vive fora do React e que pode
// mudar a qualquer momento" (aqui, o SO trocando de tema enquanto a
// página está aberta), sem o padrão setState-dentro-de-efeito que a regra
// de lint react-hooks/set-state-in-effect desencoraja. Usado só por
// ThemeToggle.tsx para decidir qual ícone mostrar quando NENHUMA escolha
// explícita de tema foi feita ainda (sem cookie "nix-theme") — a
// aparência de fato (cores) já segue prefers-color-scheme via puro CSS em
// globals.css, isto é só para o ícone do botão concordar com o que a tela
// já está mostrando.
function subscribe(callback: () => void): () => void {
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  mq.addEventListener("change", callback);
  return () => mq.removeEventListener("change", callback);
}

function getSnapshot(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

// SSR não tem acesso ao SO do navegador — um valor fixo e consistente é
// o certo aqui (useSyncExternalStore reconcilia a diferença pós-hidratação
// sem disparar o aviso de mismatch, exatamente o propósito deste terceiro
// argumento).
function getServerSnapshot(): boolean {
  return false;
}

export function usePrefersDark(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}
