import { useEffect } from "react";
import { SEVERITIES, SEV_LABEL, STATUS_LABEL } from "../lib";


export function SevBadge({ sev }) {
  const k = SEVERITIES.includes(sev) ? sev : "informational";
  return <span className={`badge sev-${k}`}>{SEV_LABEL[k]}</span>;
}

export function Pill({ value, label }) {
  return <span className={`badge st-${value}`}>{label ?? STATUS_LABEL[value] ?? value}</span>;
}

export function Spinner() {
  return <span className="spin" aria-label="Loading" />;
}

export function Loading({ text = "Loading" }) {
  return <div className="loading"><Spinner /> <span style={{ marginLeft: 8 }}>{text}</span></div>;
}

export function Notice({ kind = "err", children }) {
  if (!children) return null;
  return <div className={`notice ${kind}`} role={kind === "err" ? "alert" : "status"}>{children}</div>;
}

export function Empty({ title, children }) {
  return <div className="empty"><h3>{title}</h3><div>{children}</div></div>;
}

export function Modal({ title, onClose, children, footer, wide }) {
  const close = typeof onClose === "function" ? onClose : () => {};
  useEffect(() => {
    const h = (e) => e.key === "Escape" && close();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [close]);
  return (
    <div className="modal-bg" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div className={`modal${wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-h"><h3>{title}</h3><button className="btn ghost sm" onClick={close}>Close</button></div>
        <div className="modal-b">{children}</div>
        {footer && <div className="modal-f">{footer}</div>}
      </div>
    </div>
  );
}

export function Confirm({ title, message, confirmLabel = "Delete", busy, onConfirm, onCancel }) {
  return (
    <Modal
      title={title}
      onClose={onCancel}
      footer={<>
        <button className="btn" onClick={onCancel}>Cancel</button>
        <button className="btn danger" disabled={busy} onClick={onConfirm}>{busy ? "Working" : confirmLabel}</button>
      </>}
    >
      <p style={{ margin: 0 }}>{message}</p>
    </Modal>
  );
}

export function SevChips({ counts = {} }) {
  const c = counts.critical || 0, h = counts.high || 0, m = counts.medium || 0;
  const cls = (n, k) => `chip ${n ? k : "z"}`;
  return (
    <div className="chips" title="Critical / High / Medium">
      <span className={cls(c, "c")}>{c}</span>
      <span className={cls(h, "h")}>{h}</span>
      <span className={cls(m, "m")}>{m}</span>
    </div>
  );
}




export function ProgramFlags({ flags = [], kernelObserved = false, compact = false, kernelLabel = "KERNEL COMPONENT" }) {
  const items = Array.isArray(flags) ? flags : [];
  if (!items.length && !kernelObserved) return <span className="muted-copy">—</span>;
  return <div className={`program-flags${compact ? " compact" : ""}`}>
    {items.map((f) => <span key={f.key} className={`program-flag flag-${f.category || "software"}`} title={`${f.label} · ${f.match_basis || "classified from endpoint metadata"}`}>
      {f.label}
    </span>)}
    {kernelObserved && <span className="program-flag flag-kernel" title="A matching kernel/driver component was observed in collected endpoint evidence.">{kernelLabel}</span>}
  </div>;
}
