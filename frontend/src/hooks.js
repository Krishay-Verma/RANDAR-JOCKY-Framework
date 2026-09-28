import { useCallback, useEffect, useRef, useState } from "react";

/** Load async data; `reload()` refetches. Ignores results after unmount. */
export function useLoad(fn, deps = [], intervalMs = 0) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const alive = useRef(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setState((s) => ({ ...s, loading: true }));
      try {
        const data = await run();
        if (alive.current) setState({ data, error: null, loading: false });
      } catch (e) {
        if (alive.current) setState((s) => ({ data: silent ? s.data : null, error: e, loading: false }));
      }
    },
    [run],
  );

  useEffect(() => {
    alive.current = true;
    load();
    let t;
    if (intervalMs) t = setInterval(() => load(true), intervalMs);
    return () => {
      alive.current = false;
      if (t) clearInterval(t);
    };
  }, [load, intervalMs]);

  return { ...state, reload: () => load(false) };
}
