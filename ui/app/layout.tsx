import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RedHive — Autonomous Pentest",
  description: "Autonomous multi-agent pentest platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
