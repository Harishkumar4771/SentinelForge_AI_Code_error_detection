"use client";

import { useMemo, useState } from "react";

import { Card, EmptyState, SeverityBadge, StatusPill } from "@/components/ui";
import type { ReportFinding, ReportFix } from "@/lib/api";

/**
 * Findings list.
 *
 * Two rules drive the layout:
 *  - A verified fix is visually distinct from a proposed one, because they are
 *    not the same claim.
 *  - Failed gates are shown, not hidden. A patch that applied but made the
 *    rescan worse must not read like a patch that worked.
 */

const FILTERS = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "verified", label: "Verified fixes" },
  { key: "unverified", label: "Not verified" },
] as const;

type FilterKey = (typeof FILTERS)[number]["key"];

function GateList({ fix }: { fix: ReportFix }) {
  if (fix.gates.length === 0) {
    return (
      <p className="text-xs text-warn">
        No gate results were recorded for this patch, so its status is unconfirmed.
      </p>
    );
  }
  return (
    <table className="w-full text-left text-xs">
      <thead>
        <tr className="text-ink-faint">
          <th className="w-20 py-1 font-medium">Gate</th>
          <th className="w-16 py-1 font-medium">Result</th>
          <th className="py-1 font-medium">Evidence</th>
        </tr>
      </thead>
      <tbody className="align-top">
        {fix.gates.map((gate) => (
          <tr key={gate.gate} className="border-t border-line/60">
            <td className="py-1.5 font-mono text-ink-dim">{gate.gate}</td>
            <td className="py-1.5">
              <span className={gate.passed ? "text-ok" : "text-critical"}>
                {gate.passed ? "PASS" : "FAIL"}
              </span>
            </td>
            <td className="py-1.5 text-ink-dim">{gate.detail || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function FixPanel({ fix }: { fix: ReportFix }) {
  return (
    <div className="mt-3 space-y-3 rounded-lg border border-line bg-panel-2 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase ${
            fix.verified
              ? "border-ok/35 bg-ok/12 text-ok"
              : "border-warn/35 bg-warn/12 text-warn"
          }`}
        >
          {fix.verified ? "Verified" : "Not verified"}
        </span>
        <span className="text-xs text-ink-dim">{fix.assurance}</span>
      </div>

      {fix.reason && <p className="text-xs text-warn">Reason: {fix.reason}</p>}
      {fix.explanation && <p className="text-sm text-ink">{fix.explanation}</p>}

      <GateList fix={fix} />

      {fix.diff && (
        <details className="group">
          <summary className="cursor-pointer font-mono text-xs text-accent">
            Patch diff ({fix.file_path})
          </summary>
          <pre className="mt-2 max-h-96 overflow-auto rounded border border-line bg-canvas p-3 font-mono text-xs leading-relaxed whitespace-pre">
            {fix.diff}
          </pre>
        </details>
      )}
    </div>
  );
}

function FindingRow({ finding }: { finding: ReportFinding }) {
  const [open, setOpen] = useState(false);
  const fix = finding.fix;

  return (
    <li className="px-4 py-3">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-start gap-3 text-left"
      >
        <span className="mt-0.5 shrink-0 font-mono text-xs text-ink-faint">
          {open ? "▾" : "▸"}
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            {finding.cwe && (
              <span className="font-mono text-[11px] text-ink-faint">{finding.cwe}</span>
            )}
            {finding.verified && (
              <span className="rounded border border-ok/35 bg-ok/12 px-1.5 py-0.5 font-mono text-[11px] text-ok uppercase">
                fix verified
              </span>
            )}
          </span>
          <span className="mt-1 block text-sm font-medium">{finding.title}</span>
          <span className="mt-0.5 block font-mono text-xs text-ink-faint">
            {finding.location} · {finding.category}
            {finding.owasp ? ` · ${finding.owasp}` : ""}
          </span>
        </span>
      </button>

      {open && (
        <div className="mt-3 space-y-3 pl-6">
          <p className="text-sm text-ink-dim">{finding.description}</p>

          {finding.impact && (
            <p className="text-sm">
              <span className="font-semibold text-ink">Impact. </span>
              {finding.impact}
            </p>
          )}
          {finding.recommendation && (
            <p className="text-sm">
              <span className="font-semibold text-ink">Recommendation. </span>
              {finding.recommendation}
            </p>
          )}

          {finding.code_snippet && (
            <pre className="max-h-64 overflow-auto rounded border border-line bg-canvas p-3 font-mono text-xs leading-relaxed whitespace-pre">
              {finding.code_snippet}
            </pre>
          )}

          <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-ink-faint">
            <span>certainty: {finding.certainty} ({finding.confidence.toFixed(2)})</span>
            <span>detected by: {finding.detected_by.join(", ") || "unknown"}</span>
            {finding.tools.length > 0 && <span>tools: {finding.tools.join(", ")}</span>}
            <span>status: {finding.status}</span>
          </div>

          {finding.tests.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold tracking-wide text-ink-faint uppercase">
                Generated tests
              </h4>
              <ul className="mt-1 space-y-1">
                {finding.tests.map((test) => (
                  <li key={test.name} className="flex items-center gap-2 text-xs text-ink-dim">
                    <StatusPill status={test.status} />
                    <span className="font-mono">{test.name}</span>
                    {test.is_exploit_test && (
                      <span className="text-critical">exploit test</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {fix ? (
            <FixPanel fix={fix} />
          ) : (
            <p className="text-xs text-ink-faint">No fix was proposed for this finding.</p>
          )}
        </div>
      )}
    </li>
  );
}

export function FindingsList({ findings }: { findings: ReportFinding[] }) {
  const [filter, setFilter] = useState<FilterKey>("all");

  const counts = useMemo(() => {
    const base: Record<string, number> = { all: findings.length };
    for (const finding of findings) {
      const key = finding.severity.toLowerCase();
      base[key] = (base[key] ?? 0) + 1;
    }
    base.verified = findings.filter((f) => f.verified).length;
    base.unverified = findings.length - base.verified;
    return base;
  }, [findings]);

  const visible = useMemo(() => {
    switch (filter) {
      case "all":
        return findings;
      case "verified":
        return findings.filter((f) => f.verified);
      case "unverified":
        return findings.filter((f) => !f.verified);
      default:
        return findings.filter((f) => f.severity.toLowerCase() === filter);
    }
  }, [findings, filter]);

  return (
    <Card
      title="Findings"
      action={
        <div className="flex flex-wrap gap-1">
          {FILTERS.filter((option) => counts[option.key]).map((option) => (
            <button
              key={option.key}
              type="button"
              onClick={() => setFilter(option.key)}
              className={`rounded px-2 py-1 font-mono text-[11px] transition ${
                filter === option.key
                  ? "bg-accent/20 text-accent"
                  : "text-ink-dim hover:bg-white/5 hover:text-ink"
              }`}
            >
              {option.label} {counts[option.key]}
            </button>
          ))}
        </div>
      }
    >
      {visible.length === 0 ? (
        <EmptyState title="No findings match this filter." />
      ) : (
        <ul className="divide-y divide-line">
          {visible.map((finding) => (
            <FindingRow key={finding.id} finding={finding} />
          ))}
        </ul>
      )}
    </Card>
  );
}
