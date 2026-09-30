import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client";

const PREFIX = "randar.investigation-job.";
const TERMINAL = new Set(["complete", "partial", "cancelled", "error"]);

export function useInvestigationJob(scope) {
  const key = `${PREFIX}${scope}`;
  const alive = useRef(true);
  const timer = useRef(null);
  const [job, setJob] = useState(null);
  const [error, setError] = useState("");

  const clear = useCallback(() => { try { sessionStorage.removeItem(key); } catch (_) {} }, [key]);
  const watch = useCallback(async (jobId) => {
    try {
      const current = await api.investigationJob(jobId);
      if (!alive.current) return;
      setJob(current);
      if (TERMINAL.has(current.status)) {
        clear();
        return;
      }
      timer.current = window.setTimeout(() => watch(jobId), 1000);
    } catch (e) {
      if (!alive.current) return;
      // Polling failures are transient; the server job is independent of the page.
      setError(e.message);
      timer.current = window.setTimeout(() => watch(jobId), 2500);
    }
  }, [clear]);

  useEffect(() => {
    alive.current = true;
    try {
      const stored = sessionStorage.getItem(key);
      if (stored) watch(stored);
    } catch (_) {}
    return () => {
      alive.current = false;
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [key, watch]);

  const start = useCallback(async (script, networkSourceId = null) => {
    setError("");
    if (timer.current) window.clearTimeout(timer.current);
    try {
      const created = await api.runAsync(script, networkSourceId);
      try { sessionStorage.setItem(key, created.job_id); } catch (_) {}
      if (!alive.current) return created;
      setJob(created);
      watch(created.job_id);
      return created;
    } catch (e) {
      if (alive.current) setError(e.message);
      throw e;
    }
  }, [key, watch]);

  const cancel = useCallback(async () => {
    const jobId = job?.job_id;
    if (!jobId) return null;
    const current = await api.cancelInvestigationJob(jobId);
    if (alive.current) setJob(current);
    if (TERMINAL.has(current.status)) clear();
    return current;
  }, [clear, job]);

  return { start, cancel, job, error, busy: Boolean(job && !TERMINAL.has(job.status)) };
}
