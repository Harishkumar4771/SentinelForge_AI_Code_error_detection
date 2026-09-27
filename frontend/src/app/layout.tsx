import type { Metadata } from "next";
import Link from "next/link";
import { Geist, Geist_Mono } from "next/font/google";

import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "SentinelForge — verified code fixes",
  description:
    "Scan a repository for vulnerabilities and bugs, and only call a fix verified when all four gates pass.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased dark`}>
      <body className="flex min-h-full flex-col">
        <header className="sticky top-0 z-50 border-b border-line bg-canvas/60 backdrop-blur-md shadow-sm">
          <div className="mx-auto flex w-full max-w-6xl items-center gap-4 px-6 py-4">
            <Link href="/" className="text-lg font-bold tracking-tight text-ink flex items-center gap-2 transition hover:opacity-80">
              <span className="bg-accent/20 text-accent p-1.5 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </span>
              Sentinel<span className="text-accent">Forge</span>
            </Link>
            <span className="text-xs font-medium text-accent bg-accent/10 px-2 py-0.5 rounded-full border border-accent/20">Verified fixes, not suggestions</span>
          </div>
        </header>
        <main className="flex-1 relative z-10">{children}</main>
        <footer className="border-t border-line bg-canvas/80 backdrop-blur-sm px-6 py-8 mt-12">
          <div className="mx-auto w-full max-w-6xl flex flex-col items-center justify-center gap-2">
            <p className="text-xs text-ink-dim max-w-2xl text-center">
              Verification executes the target repository&rsquo;s code. Check the sandbox notice on every scan before relying on a result.
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
