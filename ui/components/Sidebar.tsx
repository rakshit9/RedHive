"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";

const NAV = [
  { href: "/", label: "Dashboard", icon: "▤" },
  { href: "/scans", label: "Scans", icon: "◎" },
  { href: "/targets", label: "Targets", icon: "⌖" },
  { href: "/integrations", label: "Integrations", icon: "🔗" },
  { href: "/keys", label: "API Keys", icon: "🔑" },
];

export default function Sidebar() {
  const pathname = usePathname();
  const { me, logout } = useAuth();

  return (
    <aside className="flex w-60 flex-col border-r border-[#161d28] bg-[#090c12]">
      <div className="flex items-center gap-2.5 px-5 py-4">
        <span className="text-xl">🐝</span>
        <span className="text-lg font-bold tracking-tight text-gray-100">
          Red<span className="text-hive-accent">Hive</span>
        </span>
      </div>

      <nav className="mt-2 flex-1 space-y-1 px-3">
        {NAV.map((item) => {
          const active =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                active
                  ? "bg-hive-accent/10 text-hive-accent"
                  : "text-gray-400 hover:bg-white/5 hover:text-gray-200"
              }`}
            >
              <span className="w-5 text-center">{item.icon}</span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-[#161d28] p-3">
        <div className="rounded-lg px-3 py-2">
          <div className="truncate text-sm text-gray-200">{me?.org_name}</div>
          <div className="truncate text-xs text-gray-500">{me?.email}</div>
          <span className="mt-1.5 inline-block rounded-full bg-[#1b2330] px-2 py-0.5 text-[10px] uppercase tracking-wide text-gray-400">
            {me?.plan} plan
          </span>
        </div>
        <button
          onClick={logout}
          className="mt-1 w-full rounded-lg px-3 py-2 text-left text-sm text-gray-500 transition hover:bg-white/5 hover:text-gray-300"
        >
          ⏻ Sign out
        </button>
      </div>
    </aside>
  );
}
