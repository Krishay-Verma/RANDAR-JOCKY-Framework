import { useRef } from "react";

/** Monospace editor with a line gutter; `errorLine` highlights a line. */
export default function ScriptEditor({ value, onChange, errorLine, taRef, rows = 18 }) {
  const gutter = useRef(null);
  const lines = value.split("\n").length;
  return (
    <div className="editor">
      <div className="gutter" ref={gutter} aria-hidden="true">
        {Array.from({ length: Math.max(lines, rows) }, (_, i) => (
          <div key={i} className={errorLine === i + 1 ? "bad" : ""}>{i + 1}</div>
        ))}
      </div>
      <textarea ref={taRef} value={value} spellCheck={false} aria-label="Investigation script"
        style={{ minHeight: `${rows * 19.4 + 16}px` }} wrap="off"
        onChange={(e) => onChange(e.target.value)}
        onScroll={(e) => { if (gutter.current) gutter.current.scrollTop = e.target.scrollTop; }} />
    </div>
  );
}

