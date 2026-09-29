import { useCallback, useEffect, useRef, useState } from "react";

/** Load async data; stale requests are ignored after navigation/unmount. */
export function useLoad(fn, deps = [], intervalMs = 0) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const mounted = useRef(false);
  const generation = useRef(0);
  const activeController = useRef(null);
  const run = useCallback(fn, deps);

  const load = useCallback(
    async (silent = false) => {
      if (typeof run !== "function") {
        const err = new TypeError("RANDAR data loader is not callable.");
        if (mounted.current) setState((s) => ({ data: silent ? s.data : null, error: err, loading: false }));
        return;
      }
      const current = ++generation.current;
      activeController.current?.abort();
      if (!silent && mounted.current) setState((s) => ({ ...s, loading: true, error: null }));
      const controller = new AbortController();
      activeController.current = controller;
      try {
        // Loaders may accept an AbortSignal; legacy zero-argument loaders remain compatible.
        const data = await run(controller.signal);
        if (mounted.current && current === generation.current) setState({ data, error: null, loading: false });
      } catch (e) {
        if (e?.name === "AbortError") return;
        if (mounted.current && current === generation.current) setState((s) => ({ data: silent ? s.data : null, error: e, loading: false }));
      } finally {
        if (activeController.current === controller) activeController.current = null;
      }
    },
    [run],
  );

  useEffect(() => {
    mounted.current = true;
    const runGeneration = ++generation.current;
    void load();
    let timer;
    if (intervalMs) timer = setInterval(() => void load(true), intervalMs);
    return () => {
      mounted.current = false;
      generation.current = Math.max(generation.current, runGeneration + 1);
      activeController.current?.abort();
      activeController.current = null;
      if (timer) clearInterval(timer);
    };
  }, [load, intervalMs]);

  const reload = useCallback(() => load(false), [load]);
  return { ...state, reload };
}
