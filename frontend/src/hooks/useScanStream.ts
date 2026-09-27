"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { streamScan, type ScanEvent } from "@/lib/api";

/**
 * Subscribe to a scan's event stream.
 *
 * Two non-obvious problems this has to solve:
 *
 *  - A dropped connection looks exactly like a finished scan, so a reconnect
 *    with backoff is needed. A terminal phase stops it, otherwise a completed
 *    scan would reconnect forever.
 *  - `terminal` and the event handler are read from inside callbacks that were
 *    created in an earlier render. Holding them in refs keeps the reconnect
 *    logic reading current values instead of the values that existed when the
 *    connection opened.
 */

const TERMINAL = new Set(["completed", "failed", "cancelled"]);
const BACKOFF_MS = [1000, 2000, 5000, 10000];

export type StreamState = "connecting" | "live" | "reconnecting" | "closed";

export function useScanStream(
  scanId: string | null,
  options: { active: boolean; onEvent?: (event: ScanEvent) => void },
) {
  const { active, onEvent } = options;
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [state, setState] = useState<StreamState>("closed");
  const [lastProgress, setLastProgress] = useState<number | null>(null);
  const [terminal, setTerminal] = useState<string | null>(null);

  const attempt = useRef(0);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const close = useRef<(() => void) | null>(null);
  const terminalRef = useRef<string | null>(null);
  const handler = useRef(onEvent);

  // Refs are written from an effect, not during render, so a render that is
  // thrown away cannot leave a callback pointing at a stale handler.
  useEffect(() => {
    handler.current = onEvent;
  }, [onEvent]);

  // Reset accumulated state when the scan changes. Done during render, which
  // React explicitly supports for "adjust state when an input changes", and it
  // avoids an extra render pass from an effect.
  const [seenScanId, setSeenScanId] = useState(scanId);
  if (seenScanId !== scanId) {
    setSeenScanId(scanId);
    setEvents([]);
    setLastProgress(null);
    setTerminal(null);
  }

  // Refs, unlike state, cannot be reset during a render pass, so they are
  // cleared here instead. Effects run in order, so this lands before the
  // connect effect below opens a stream for the new scan.
  useEffect(() => {
    terminalRef.current = null;
    attempt.current = 0;
  }, [scanId]);

  const shutdown = useCallback(() => {
    close.current?.();
    close.current = null;
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  // `connect` needs to re-invoke itself on a retry, but a useCallback cannot
  // reference itself in its own initialiser. The ref is filled in by an effect
  // and read only when a retry actually fires.
  const connectRef = useRef<(() => void) | null>(null);

  const connect = useCallback(() => {
    if (!scanId || !active) return;
    setState(attempt.current === 0 ? "connecting" : "reconnecting");

    close.current = streamScan(scanId, {
      onOpen: () => {
        attempt.current = 0;
        setState("live");
      },
      onEvent: (event) => {
        setEvents((previous) => [...previous, event]);
        if (typeof event.progress === "number") setLastProgress(event.progress);
        handler.current?.(event);

        if (TERMINAL.has(event.phase)) {
          terminalRef.current = event.phase;
          setTerminal(event.phase);
          shutdown();
        }
      },
      onError: () => {
        if (terminalRef.current) return;
        const wait = BACKOFF_MS[Math.min(attempt.current, BACKOFF_MS.length - 1)];
        attempt.current += 1;
        setState("reconnecting");
        shutdown();
        timer.current = setTimeout(() => connectRef.current?.(), wait);
      },
    });
  }, [scanId, active, shutdown]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    if (active && scanId) connect();
    return shutdown;
  }, [scanId, active, connect, shutdown]);

  return { events, state, lastProgress, terminal };
}
