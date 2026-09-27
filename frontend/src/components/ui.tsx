import type { ReactNode } from "react";

/**
 * Small presentational primitives shared across the dashboard.
 *
 * Kept together deliberately: severity colours, status pills and the isolation
 * banner all encode the same judgement about how much trust a result deserves,
 * and they should not drift apart between pages.
 */

const SEVERITY_STYLE: Record<string, string> = {
  critical: "text-critical bg-critical/12 border-critical/35",
  high: "text-high bg-high/12 border-high/35",
  medium: "text-medium bg-medium/12 border-medium/30",
  low: "text-low bg-low/12 border-low/30",
  info: "text-info bg-info/12 border-info/30",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toLowerCase();
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold tracking-wide uppercase ${
        SEVERITY_STYLE[key] ?? "text-ink-dim bg-white/5 border-line"
      }`}
    >
      {key}
    </span>
  );
}

const STATUS_STYLE: Record<string, string> = {
  verified: "text-ok bg-ok/12 border-ok/35",
  confirmed: "text-ok bg-ok/12 border-ok/35",
  completed: "text-ok bg-ok/12 border-ok/35",
  running: "text-accent bg-accent/12 border-accent/35",
  queued: "text-ink-dim bg-white/5 border-line",
  proposed: "text-info bg-info/12 border-info/30",
  open: "text-ink-dim bg-white/5 border-line",
  pending: "text-ink-dim bg-white/5 border-line",
  failed: "text-critical bg-critical/12 border-critical/35",
  rejected: "text-critical bg-critical/12 border-critical/35",
  cancelled: "text-ink-faint bg-white/5 border-line",
  error: "text-critical bg-critical/12 border-critical/35",
};

export function StatusPill({ status }: { status: string }) {
  const key = status.toLowerCase();
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-[11px] tracking-wide uppercase ${
        STATUS_STYLE[key] ?? "text-ink-dim bg-white/5 border-line"
      }`}
    >
      {status === "running" && <span className="pulse-dot size-1.5 rounded-full bg-accent" />}
      {status}
    </span>
  );
}

export function Card({
  title,
  action,
  children,
  className = "",
}: {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <h2 className="text-sm font-semibold tracking-wide text-ink">{title}</h2>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({
  label,
  value,
  tone = "default",
  hint,
}: {
  label: string;
  value: ReactNode;
  tone?: "default" | "ok" | "critical" | "warn" | "accent";
  hint?: string;
}) {
  const toneClass = {
    default: "text-ink",
    ok: "text-ok",
    critical: "text-critical",
    warn: "text-medium",
    accent: "text-accent",
  }[tone];
  return (
    <div className="min-w-0">
      <dt className="truncate text-[11px] tracking-wide text-ink-faint uppercase">{label}</dt>
      <dd className={`mt-0.5 font-mono text-2xl font-semibold tabular-nums ${toneClass}`}>
        {value}
        {hint && <span className="ml-1 text-xs font-normal text-ink-faint">{hint}</span>}
      </dd>
    </div>
  );
}

/**
 * The sandbox disclosure.
 *
 * This is deliberately impossible to miss and never hidden behind a toggle: a
 * fix that ran on the host is real evidence, but it is not the same claim as a
 * fix that ran in a container, and a dashboard that blurred the two would be
 * lying to its user.
 */
export function IsolationBanner({
  isolated,
  backend,
  note,
}: {
  isolated: boolean | null;
  backend?: string | null;
  note?: string | null;
}) {
  if (isolated === null) {
    return (
      <div className="panel border-warn/40 bg-warn/8 px-4 py-3 text-sm text-warn">
        <strong className="font-semibold">Sandbox isolation was not recorded.</strong>{" "}
        Treat every verification result in this report as unconfirmed.
      </div>
    );
  }
  if (isolated) {
    return (
      <div className="panel border-ok/40 bg-ok/8 px-4 py-3 text-sm text-ok">
        <strong className="font-semibold">Verified in an isolated sandbox.</strong>{" "}
        {note ?? "Target code ran inside a container, not on the host."}
      </div>
    );
  }
  return (
    <div className="panel border-warn/45 bg-warn/8 px-4 py-3 text-sm text-warn">
      <strong className="font-semibold">Not isolated.</strong>{" "}
      {note ?? "Target code ran on the host machine"}.
      {backend && <span className="text-ink-dim"> Sandbox backend: {backend}.</span>}{" "}
      <span className="text-ink-dim">
        Verified fixes are real evidence, but they are weaker than isolated results.
      </span>
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="px-4 py-10 text-center">
      <p className="text-sm text-ink-dim">{title}</p>
      {hint && <p className="mt-1 text-xs text-ink-faint">{hint}</p>}
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div
      role="alert"
      className="panel border-critical/40 bg-critical/8 px-4 py-3 text-sm text-critical"
    >
      <strong className="font-semibold">Request failed.</strong> {message}
    </div>
  );
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds - minutes * 60)}s`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (!bytes) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}
