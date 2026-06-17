import { useEffect, useState } from 'react';

/** Lightweight global toast system (replaces native alert()). */
export type ToastKind = 'success' | 'info' | 'error';
interface ToastItem { id: number; kind: ToastKind; text: string }

type Listener = (t: ToastItem) => void;
const listeners = new Set<Listener>();
let seq = 0;

export function toast(text: string, kind: ToastKind = 'success'): void {
  const item = { id: ++seq, kind, text };
  listeners.forEach((l) => l(item));
}

export function Toaster() {
  const [items, setItems] = useState<ToastItem[]>([]);
  useEffect(() => {
    const l: Listener = (t) => {
      setItems((cur) => [...cur, t]);
      setTimeout(() => setItems((cur) => cur.filter((x) => x.id !== t.id)), 4200);
    };
    listeners.add(l);
    return () => { listeners.delete(l); };
  }, []);

  const icon = (k: ToastKind) => (k === 'success' ? '✓' : k === 'error' ? '✕' : 'i');

  return (
    <div className="toaster">
      {items.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`} onClick={() => setItems((c) => c.filter((x) => x.id !== t.id))}>
          <span className="ti">{icon(t.kind)}</span>
          <span className="tt">{t.text}</span>
        </div>
      ))}
    </div>
  );
}
