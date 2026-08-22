import Link from "next/link";

const links = [
  { href: "/dashboard", label: "Visão geral" },
  { href: "/dashboard/users", label: "Usuários" },
  { href: "/dashboard/integrations", label: "Integrações" },
];

export function Sidebar() {
  return (
    <nav aria-label="Principal" className="w-56 shrink-0 border-r border-surface-border p-4">
      <div className="mb-6 px-2 text-lg font-semibold">NIX Platform</div>
      <ul className="flex flex-col gap-1">
        {links.map((link) => (
          <li key={link.href}>
            <Link
              href={link.href}
              className="block rounded-md px-3 py-2 text-sm font-medium text-foreground hover:bg-black/5 dark:hover:bg-white/5"
            >
              {link.label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
