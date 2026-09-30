import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client";

const PREFIX = "randar.forensic-job.";
const TERMINAL = new Set(["complete", "error"]);
function keyFor(scanType) { return `${PREFIX}${scanType}`; }

export function useForensicJob(scanType) {
  const [job, setJob] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const timer = useRef(null);
  const alive = useRef(true);

  const clearStored = useCallback(() => {
    try { sessionStorage.removeItem(keyFor(scanType)); } catch (_) {}
  }, [scanType]);

  const watch = useCallback(async (jobId) => {
    try {
      const current = await api.forensicJob(jobId);
      if (!alive.current) return;
      setJob(current);
      if (current.status === "complete") {
        setResult(current.result || null);
        clearStored();
        return;
      }
      if (current.status === "error") {
        setError(current.error || "Forensic scan failed.");
        clearStored();
        return;
      }
      timer.current = window.setTimeout(() => watch(jobId), 1200);
    } catch (e) {
      if (!alive.current) return;
      setError(e.message);
      // The server-side job is independent of this page. Keep trying to observe it.
      timer.current = window.setTimeout(() => watch(jobId), 2500);
    }
  }, [clearStored]);

  useEffect(() => {
    alive.current = true;
    let stored = null;
    try { stored = sessionStorage.getItem(keyFor(scanType)); } catch (_) {}
    if (stored) watch(stored);
    return () => {
      alive.current = false;
      if (timer.current) window.clearTimeout(timer.current);
      // Route changes only stop polling; they never cancel the server-side scan.
    };
  }, [scanType, watch]);

  const start = useCallback(async () => {
    setError("");
    setResult(null);
    if (timer.current) window.clearTimeout(timer.current);
    try {
      const created = await api.forensicJobCreate(scanType);
      // Persist the job id even if the user changed routes while the create
      // request was in flight. The server job must remain recoverable.
      try { sessionStorage.setItem(keyFor(scanType), created.job_id); } catch (_) {}
      if (!alive.current) return;
      setJob(created);
      watch(created.job_id);
    } catch (e) {
      if (alive.current) setError(e.message);
    }
  }, [scanType, watch]);

  return { start, job, result, error, busy: Boolean(job && !TERMINAL.has(job.status)) };
}
