/**
 * Typed client for the SentinelForge API.
 *
 * The types below are transcribed from the backend's OpenAPI schema rather than
 * written from memory, so a contract change shows up as a TypeScript error
 * instead of as a silently wrong field in the UI.
 *
 * Base URL resolution, in order:
 *   1. NEXT_PUBLIC_API_BASE_URL (set at build time, e.g. in docker compose)
 *   2. same-origin, which is what a reverse-proxied deployment needs
 */

export const API_BASE = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? ""
).replace(/\/$/, "");

/* ------------------------------------------------------------------ types */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface Project {
  id: string;
  name: string;
  description: string | null;
  status: string;
  original_filename: string | null;
  file_count: number;
  total_bytes: number;
  primary_language: string | null;
  languages: string[] | null;
  ingestion_warnings: string[] | null;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  status: ScanStatus;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  security_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  bugs_detected: number;
  tests_generated: number;
  tests_passed: number;
  tests_failed: number;
  verified_fixes: number;
  failed_fixes: number;
  ai_provider: string | null;
  duration_seconds: number | null;
  created_at: string;
  updated_at: string;
}

export interface AgentExecution {
  id: string;
  scan_id: string;
  agent_name: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  message: string | null;
  findings_count: number;
  metrics: Record<string, unknown> | null;
  error: string | null;
}

/**
 * The detail endpoint returns a wrapper, not a flattened scan, so a single
 * request is enough to render a whole result page.
 */
export interface ScanDetail {
  scan: Scan;
  findings: Finding[];
  tests: TestCase[];
  patches: Patch[];
  agents: AgentExecution[];
}

export interface Finding {
  id: string;
  scan_id: string;
  fingerprint: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  category: string;
  cwe: string | null;
  owasp: string | null;
  certainty: string;
  file_path: string | null;
  line_number: number | null;
  line_end: number | null;
  code_snippet: string | null;
  evidence: string[] | null;
  impact: string | null;
  recommendation: string | null;
  detected_by: string[] | null;
  tools: string[] | null;
  status: string;
  verified: boolean;
  is_bug: boolean;
}

export interface GateResult {
  gate: string;
  passed: boolean;
  detail: string;
  duration_ms?: number | null;
}

export interface Patch {
  id: string;
  scan_id: string;
  finding_id: string;
  attempt: number;
  original_code: string | null;
  patched_code: string | null;
  diff: string | null;
  explanation: string | null;
  files_touched: string[] | null;
  validation_status: string;
  validation_output: string | null;
  verification: Record<string, unknown> | null;
  verified: boolean;
  applied: boolean;
  duration_ms: number | null;
}

/** The four gates. A fix is "verified" only when every one of them passed. */
export const GATES = [
  "reproduced",
  "applied",
  "regression",
  "rescan",
] as const;
export type Gate = (typeof GATES)[number];

export interface TestCase {
  id: string;
  scan_id: string;
  finding_id: string | null;
  name: string;
  description: string | null;
  test_code: string;
  test_type: string;
  target_file: string | null;
  status: string;
  is_exploit_test: boolean;
  duration_ms: number | null;
}

export interface ScanEvent {
  id: string;
  scan_id: string;
  seq: number;
  agent: string | null;
  phase: string;
  status: string | null;
  progress: number | null;
  message: string;
  payload: Record<string, unknown> | null;
  created_at: string;
}

export interface ScanAccepted {
  scan_id: string;
  project_id: string;
  status: string;
  stream_url: string;
}

export interface ReportAssurance {
  isolated: boolean | null;
  sandbox_backend: string;
  note: string;
}

export interface ReportGate extends GateResult {
  gate: string;
}

export interface ReportFix {
  file_path: string;
  validation_status: string;
  verified: boolean;
  applied: boolean;
  /** Honest one-line statement of what the fix is worth. */
  assurance: string;
  isolated: boolean | null;
  files_touched: string[];
  gates: ReportGate[];
  reason: string;
  explanation: string;
  diff: string;
}

export interface ReportFinding {
  id: string;
  fingerprint: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  verified: boolean;
  is_bug: boolean;
  certainty: string;
  confidence: number;
  location: string;
  cwe: string | null;
  owasp: string | null;
  detected_by: string[];
  tools: string[];
  description: string;
  impact: string;
  recommendation: string;
  code_snippet: string;
  tests: ReportTest[];
  fix: ReportFix | null;
}

export interface ReportTest {
  name: string;
  test_type: string;
  target_file: string | null;
  status: string;
  is_exploit_test: boolean;
  finding_id: string | null;
  description: string;
  code: string;
  duration_ms: number | null;
}

/**
 * A patch that could not be matched to any finding. Deliberately a narrower
 * shape than ReportFix: the renderer only summarises these, because there is no
 * finding to attach gates or evidence to.
 */
export interface ReportOrphanPatch {
  finding_id: string;
  file_path: string;
  validation_status: string;
  verified: boolean;
}

export interface ReportSummary {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  bugs: number;
  security_score: number;
  tests_generated: number;
  verified_fixes: number;
  failed_fixes: number;
  fix_coverage_pct: number;
}

export interface ScanReport {
  scan_id: string;
  project: Record<string, unknown>;
  scan: Record<string, unknown>;
  generated_at: string;
  assurance: ReportAssurance;
  summary: ReportSummary;
  findings: ReportFinding[];
  orphan_patches: ReportOrphanPatch[];
  tests: ReportTest[];
  agents: AgentExecution[];
  timeline: ScanEvent[];
}

/* ----------------------------------------------------------------- errors */

/** An error that carries the API's own explanation, not a bare status code. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly detail?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function unwrap<T>(response: Response): Promise<T> {
  if (response.ok) {
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }
  let detail: unknown;
  let message = `${response.status} ${response.statusText}`;
  try {
    const body = await response.json();
    detail = body?.detail;
    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail) && detail.length > 0) {
      // FastAPI validation errors: surface the first field message.
      const first = detail[0] as { msg?: string; loc?: unknown[] };
      const loc = Array.isArray(first.loc) ? first.loc.slice(1).join(".") : "";
      message = loc ? `${loc}: ${first.msg}` : (first.msg ?? message);
    }
  } catch {
    // Non-JSON error body; the status line is all we have.
  }
  throw new ApiError(response.status, message, detail);
}

function url(path: string, params?: Record<string, string | number | boolean | undefined>) {
  const target = new URL(`${API_BASE}${path}`, "http://localhost");
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== "") target.searchParams.set(key, String(value));
  }
  // Collapse back to a path when we are same-origin, so cookies and relative
  // deployments behave.
  const suffix = target.pathname + target.search;
  return `${API_BASE}${suffix}`;
}

/* --------------------------------------------------------------- requests */

export const api = {
  health: () => fetch(url("/api/health")).then(unwrap),

  listProjects: (limit = 50) =>
    fetch(url("/api/projects", { limit })).then(unwrap<Project[]>),

  getProject: (id: string) => fetch(url(`/api/projects/${id}`)).then(unwrap<Project>),

  /**
   * Upload a repository archive. Kept separate from createProject so the
   * browser shows upload progress rather than an indeterminate spinner.
   */
  uploadRepository: (
    file: File,
    onProgress?: (fraction: number) => void,
  ) =>
    new Promise<Project>((resolve, reject) => {
      const form = new FormData();
      form.append("file", file);

      const xhr = new XMLHttpRequest();
      xhr.open("POST", url("/api/projects/upload"));
      xhr.responseType = "json";

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && onProgress) {
          onProgress(event.loaded / event.total);
        }
      };
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(xhr.response as Project);
        } else {
          const detail = xhr.response?.detail;
          reject(
            new ApiError(
              xhr.status,
              typeof detail === "string" ? detail : `${xhr.status} upload failed`,
              detail,
            ),
          );
        }
      };
      xhr.onerror = () => reject(new ApiError(0, "Network error during upload"));
      xhr.send(form);
    }),

  cloneRepository: (url_: string, branch?: string) =>
    fetch(url("/api/projects/clone"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url_, branch }),
    }).then(unwrap<Project>),

  startScan: (projectId: string, verify = true) =>
    fetch(url(`/api/scans/projects/${projectId}`, { verify }), { method: "POST" }).then(
      unwrap<ScanAccepted>,
    ),

  listScans: (projectId?: string, limit = 50) =>
    fetch(url("/api/scans", { project_id: projectId, limit })).then(unwrap<Scan[]>),

  getScan: (id: string) => fetch(url(`/api/scans/${id}`)).then(unwrap<ScanDetail>),

  listFindings: (
    scanId: string,
    filters: { severity?: string; verified?: boolean } = {},
  ) =>
    fetch(
      url(`/api/scans/${scanId}/findings`, {
        severity: filters.severity,
        verified: filters.verified,
      }),
    ).then(unwrap<Finding[]>),

  listPatches: (scanId: string) =>
    fetch(url(`/api/scans/${scanId}/patches`)).then(unwrap<Patch[]>),

  listTests: (scanId: string) =>
    fetch(url(`/api/scans/${scanId}/tests`)).then(unwrap<TestCase[]>),

  listEvents: (scanId: string) =>
    fetch(url(`/api/scans/${scanId}/events`)).then(unwrap<ScanEvent[]>),

  /** The full audit report. The richest source of gate and isolation detail. */
  getReport: (scanId: string) =>
    fetch(url(`/api/scans/${scanId}/report`, { format: "json" })).then(
      unwrap<ScanReport>,
    ),

  cancelScan: (scanId: string) =>
    fetch(url(`/api/scans/${scanId}/cancel`), { method: "POST" }).then(unwrap),

  reportUrl: (scanId: string, format: "md" | "html" | "json", download = false) =>
    url(`/api/scans/${scanId}/report`, { format, download: download || undefined }),
};

/* -------------------------------------------------------------------- SSE */

export interface StreamHandlers {
  onEvent: (event: ScanEvent) => void;
  onError?: (error: Event) => void;
  onOpen?: () => void;
}

/**
 * Subscribe to a scan's event stream.
 *
 * EventSource cannot be pointed at a different origin with credentials, so when
 * the API lives on another host we fall back to fetch + a manual SSE parse.
 * Returns a function that closes the connection.
 */
export function streamScan(scanId: string, handlers: StreamHandlers): () => void {
  const target = url(`/api/scans/${scanId}/stream`);

  if (!API_BASE) {
    const source = new EventSource(target);
    source.onopen = () => handlers.onOpen?.();
    source.onmessage = (message) => {
      try {
        handlers.onEvent(JSON.parse(message.data) as ScanEvent);
      } catch {
        // A malformed frame should not tear down a live stream.
      }
    };
    source.onerror = (event) => handlers.onError?.(event);
    return () => source.close();
  }

  const controller = new AbortController();
  void (async () => {
    try {
      const response = await fetch(target, {
        signal: controller.signal,
        headers: { Accept: "text/event-stream" },
      });
      if (!response.ok || !response.body) throw new Error(`stream ${response.status}`);
      handlers.onOpen?.();
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        buffer += decoder.decode(value, { stream: true });
        // SSE frames are separated by a blank line.
        let split: number;
        while ((split = buffer.indexOf("\n\n")) !== -1) {
          const frame = buffer.slice(0, split);
          buffer = buffer.slice(split + 2);
          const data = frame
            .split("\n")
            .filter((line) => line.startsWith("data:"))
            .map((line) => line.slice(5).trim())
            .join("\n");
          if (!data) continue;
          try {
            handlers.onEvent(JSON.parse(data) as ScanEvent);
          } catch {
            // Ignore a partial or non-JSON frame rather than dropping the stream.
          }
        }
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        handlers.onError?.(error as Event);
      }
    }
  })();
  return () => controller.abort();
}
