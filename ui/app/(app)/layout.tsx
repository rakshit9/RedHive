"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import Sidebar from "@/components/Sidebar";

export default function AppLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { ready, authed } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (ready && !authed) router.replace("/login");
  }, [ready, authed, router]);

  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-gray-500">
        <span className="pulse-dot">Loading…</span>
      </div>
    );
  }
  if (!authed) return null;

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 overflow-x-hidden">{children}</main>
    </div>
  );
}
