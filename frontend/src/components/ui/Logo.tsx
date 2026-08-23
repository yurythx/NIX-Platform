// Marca do NIX Platform — mesmo desenho (badge arredondado, gradiente
// roxo, monograma "N" em blocos geométricos, glow no canto, borda fina)
// do favicon em app/icon.svg; os dois são deliberadamente o mesmo
// desenho, só que este aqui é JSX inline (não um <img src="/icon.svg">)
// pra não pagar uma requisição de rede extra por um asset tão pequeno e
// pra poder redimensionar via prop sem depender de um arquivo à parte.
// Substitui o antigo "N" escrito à mão dentro de uma <span> com
// bg-primary, repetido em Topbar/login/página inicial/sobre — um único
// componente, uma única fonte de verdade pro visual da marca.
export function Logo({ size = 32, className = "" }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 28 28"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="NIX Platform"
      className={`shrink-0 ${className}`}
    >
      <defs>
        <linearGradient id="nix-logo-bg" x1="2" y1="2" x2="26" y2="26" gradientUnits="userSpaceOnUse">
          <stop stopColor="#2a1152" />
          <stop offset="1" stopColor="#7c3aed" />
        </linearGradient>
        <linearGradient id="nix-logo-shadow" x1="3" y1="3" x2="25" y2="25" gradientUnits="userSpaceOnUse">
          <stop stopColor="rgba(255,255,255,0.14)" />
          <stop offset="1" stopColor="rgba(0,0,0,0.22)" />
        </linearGradient>
        <radialGradient id="nix-logo-glow" cx="21" cy="7" r="8" gradientUnits="userSpaceOnUse">
          <stop stopColor="#e9d5ff" stopOpacity="0.85" />
          <stop offset="1" stopColor="#e9d5ff" stopOpacity="0" />
        </radialGradient>
      </defs>
      <rect x="1" y="1" width="26" height="26" rx="8" fill="url(#nix-logo-bg)" />
      <rect x="1" y="1" width="26" height="26" rx="8" fill="url(#nix-logo-shadow)" />
      <circle cx="21" cy="7" r="8" fill="url(#nix-logo-glow)" />
      <rect x="7" y="6.5" width="3.3" height="15" fill="#F8FAFC" />
      <rect x="17.7" y="6.5" width="3.3" height="15" fill="#F8FAFC" />
      <polygon points="10.3,6.5 13.7,6.5 17.7,21.5 14.3,21.5" fill="#F8FAFC" />
      <rect
        x="1.5"
        y="1.5"
        width="25"
        height="25"
        rx="7.5"
        fill="none"
        stroke="rgba(255,255,255,0.18)"
        strokeWidth="0.75"
      />
    </svg>
  );
}
