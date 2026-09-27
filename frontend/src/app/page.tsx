"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { Card, EmptyState, ErrorNote, StatusPill, formatBytes, formatDuration } from "@/components/ui";
import { api, type Project, type Scan } from "@/lib/api";

type Phase = "idle" | "uploading" | "cloning" | "scanning" | "redirecting" | "error";

const ACCEPT = ".zip,.tar,.tar.gz,.tgz";

export default function ProjectsPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState(0);
  const [file, setFile] = useState<File | null>(null);
  const [githubUrl, setGithubUrl] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [message, setMessage] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.listProjects(), api.listScans()])
      .then(([loadedProjects, loadedScans]) => {
        if (cancelled) return;
        setProjects(loadedProjects);
        setScans(loadedScans);
        setError(null);
      })
      .catch((cause: unknown) => {
        if (cancelled) return;
        setError(cause);
        setProjects([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const pick = (chosen: File | null) => {
    if (!chosen) return;
    const name = chosen.name.toLowerCase();
    if (!name.endsWith(".zip") && !name.endsWith(".tar") && !name.endsWith(".tgz") && !name.endsWith(".tar.gz")) {
      setError(new Error("Upload a .zip, .tar, .tar.gz or .tgz archive of the repository."));
      return;
    }
    setError(null);
    setFile(chosen);
    setGithubUrl(""); // Clear github url when a file is picked
    setProgress(0);
    setPhase("idle");
  };

  const handleGithubChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setGithubUrl(e.target.value);
    if (e.target.value) {
      setFile(null); // Clear file when github url is typed
    }
  };

  const run = async () => {
    if (!file && !githubUrl) return;
    try {
      let project: Project;
      
      if (file) {
        setPhase("uploading");
        setMessage(`Uploading ${file.name}…`);
        project = await api.uploadRepository(file, setProgress);
      } else {
        setPhase("cloning");
        setMessage(`Cloning ${githubUrl}…`);
        project = await api.cloneRepository(githubUrl);
      }
      
      setPhase("scanning");
      setMessage("Starting autonomous scan…");
      const accepted = await api.startScan(project.id, true);
      
      setPhase("redirecting");
      router.push(`/scans/${accepted.scan_id}`);
    } catch (cause) {
      setPhase("error");
      setError(cause);
    }
  };

  const busy = phase === "uploading" || phase === "cloning" || phase === "scanning" || phase === "redirecting";

  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-12 fade-in">
      <div className="mb-10 text-center">
        <h1 className="text-4xl font-bold tracking-tight text-gradient mb-3">Autonomous Code Security</h1>
        <p className="text-lg text-ink-dim max-w-2xl mx-auto">
          Detect vulnerabilities, generate fixes, and verify them in a sandbox. All before you merge.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr_1.2fr]">
        <Card title="Start a Scan" className="flex flex-col">
          <div className="p-6 flex-1 flex flex-col gap-6">
            
            {/* GitHub URL Input */}
            <div>
              <label htmlFor="github-url" className="block text-sm font-medium text-ink-dim mb-2">
                GitHub Repository URL
              </label>
              <input
                id="github-url"
                type="url"
                value={githubUrl}
                onChange={handleGithubChange}
                placeholder="https://github.com/owner/repo"
                className="w-full rounded-lg border border-line bg-canvas/50 px-4 py-2.5 text-sm text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent transition-all"
                disabled={busy}
              />
            </div>

            <div className="relative flex items-center justify-center">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-line"></div>
              </div>
              <div className="relative bg-panel px-3 text-xs text-ink-faint uppercase font-medium">Or</div>
            </div>

            {/* File Upload Dropzone */}
            <div>
              <label className="block text-sm font-medium text-ink-dim mb-2">
                Upload Archive
              </label>
              <button
                type="button"
                onClick={() => inputRef.current?.click()}
                onDragOver={(event) => {
                  event.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => {
                  event.preventDefault();
                  setDragging(false);
                  pick(event.dataTransfer.files[0] ?? null);
                }}
                disabled={busy}
                className={`flex w-full flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-10 text-center transition-all duration-200 ${
                  dragging ? "border-accent bg-accent/10 scale-[1.02]" : "border-line hover:border-ink-faint hover:bg-white/5"
                } ${file ? "bg-accent-soft border-accent/50" : ""} ${busy ? "opacity-50 cursor-not-allowed" : ""}`}
              >
                <div className={`p-3 rounded-full ${file ? 'bg-accent/20 text-accent' : 'bg-white/5 text-ink-faint'}`}>
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                  </svg>
                </div>
                <div>
                  <span className="text-sm font-medium text-ink block mb-1">
                    {file ? file.name : "Drop an archive here, or click to choose"}
                  </span>
                  <span className="font-mono text-xs text-ink-dim">
                    {file ? formatBytes(file.size) : ACCEPT}
                  </span>
                </div>
              </button>
              <input
                ref={inputRef}
                type="file"
                accept={ACCEPT}
                className="sr-only"
                onChange={(event) => pick(event.target.files?.[0] ?? null)}
              />
            </div>

            {/* Progress Bar */}
            {(phase === "uploading" || phase === "cloning" || progress > 0) && phase !== "error" && (
              <div className="mt-2 fade-in">
                <div className="h-1.5 overflow-hidden rounded-full bg-line">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-accent to-info transition-[width] duration-300 ease-out"
                    style={{ width: `${phase === 'cloning' ? 100 : Math.round(progress * 100)}%` }}
                  />
                </div>
                <p className="mt-2 text-xs text-ink-dim text-center font-medium flex items-center justify-center gap-2">
                  <span className="pulse-dot size-1.5 rounded-full bg-accent" />
                  {message || `Processing… ${Math.round(progress * 100)}%`}
                </p>
              </div>
            )}

            {/* Actions */}
            <div className="mt-auto pt-4 flex items-center gap-3">
              <button
                type="button"
                onClick={run}
                disabled={(!file && !githubUrl) || busy}
                className="btn-primary flex-1 rounded-lg px-4 py-2.5 text-sm font-semibold tracking-wide disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {phase === "uploading" ? "Uploading…" 
                 : phase === "cloning" ? "Cloning…"
                 : phase === "scanning" ? "Initializing Scan…"
                 : "Start Security Scan"}
              </button>
              {(file || githubUrl) && !busy && (
                <button
                  type="button"
                  onClick={() => { setFile(null); setGithubUrl(""); }}
                  className="rounded-lg px-4 py-2.5 text-sm font-medium text-ink-dim transition hover:bg-white/10 hover:text-ink"
                >
                  Clear
                </button>
              )}
            </div>
          </div>
        </Card>

        <Card title="Recent Scans" className="flex flex-col">
          {scans.length === 0 ? (
            <div className="flex-1 flex items-center justify-center">
              <EmptyState title="No scans yet" hint="Upload a repository or provide a GitHub URL to start." />
            </div>
          ) : (
            <ul className="divide-y divide-line overflow-auto max-h-[500px]">
              {scans.map((scan) => {
                const project = projects?.find((p) => p.id === scan.project_id);
                return (
                  <li key={scan.id} className="group">
                    <Link
                      href={`/scans/${scan.id}`}
                      className="flex items-center justify-between gap-4 px-5 py-4 transition-colors hover:bg-white/5"
                    >
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-ink group-hover:text-accent transition-colors">
                          {project?.name ?? scan.project_id}
                        </p>
                        <p className="mt-1 font-mono text-[11px] text-ink-dim flex items-center gap-2">
                          <span className="bg-critical/10 text-critical px-1.5 py-0.5 rounded">{scan.bugs_detected} bugs</span>
                          <span className="bg-ok/10 text-ok px-1.5 py-0.5 rounded">{scan.verified_fixes} verified</span>
                          <span className="text-ink-faint ml-1">{formatDuration(scan.duration_seconds)}</span>
                        </p>
                      </div>
                      <StatusPill status={scan.status} />
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>

      {error !== null && (
        <div className="mt-6 fade-in">
          <ErrorNote error={error} />
        </div>
      )}

      <div className="mt-8">
        <Card title="Project Library">
          {projects === null ? (
            <EmptyState title="Loading…" />
          ) : projects.length === 0 ? (
            <EmptyState title="No projects yet." />
          ) : (
            <ul className="divide-y divide-line grid sm:grid-cols-2 md:grid-cols-3 border-t-0">
              {projects.map((project) => (
                <li key={project.id} className="flex flex-col gap-2 px-5 py-4 hover:bg-white/5 transition-colors border-b border-line sm:border-b-0 sm:border-r last:border-b-0 sm:last:border-r-0">
                  <div className="flex items-center justify-between">
                    <p className="truncate text-sm font-medium">{project.name}</p>
                    <StatusPill status={project.status} />
                  </div>
                  <p className="font-mono text-[11px] text-ink-dim">
                    {project.file_count} files · {formatBytes(project.total_bytes)}
                    {project.primary_language ? ` · ${project.primary_language}` : ""}
                  </p>
                  {project.ingestion_warnings && project.ingestion_warnings.length > 0 && (
                    <p className="mt-1 text-[11px] text-warn bg-warn/10 px-2 py-1 rounded inline-block w-fit">
                      {project.ingestion_warnings.length} ingestion warning(s)
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
