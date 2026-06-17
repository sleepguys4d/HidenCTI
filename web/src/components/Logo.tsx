import sec4dataLogo from '../assets/sec4data-logo.png';

/** SOC Xpert product mark — shield + crosshair "X" + radar dot. */
export function XpertMark({ size = 40 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" className="xpert-mark">
      <defs>
        <linearGradient id="xg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#19E3D4" /><stop offset="1" stopColor="#4F8DFF" />
        </linearGradient>
      </defs>
      <path d="M32 4 L54 12 V30 C54 44 44 54 32 60 C20 54 10 44 10 30 V12 Z"
        fill="#0C1521" stroke="url(#xg)" strokeWidth={2.5} />
      <circle cx="32" cy="31" r="15" stroke="url(#xg)" strokeWidth={1} opacity={0.3} />
      <path d="M22 21 L42 41 M42 21 L22 41" stroke="url(#xg)" strokeWidth={4.5} strokeLinecap="round" />
      <circle cx="32" cy="31" r="3.4" fill="#0C1521" stroke="#19E3D4" strokeWidth={2} />
    </svg>
  );
}

/** Full SOC Xpert lockup for the top bar. */
export function XpertLogo() {
  return (
    <div className="product-lockup">
      <XpertMark size={38} />
      <div className="product">
        <div className="p1">SOC <span>Xpert</span></div>
        <div className="p2">Unified Security Operations</div>
      </div>
    </div>
  );
}

/** Sec4data signature — uses the official brand asset. */
export function Sec4dataSignature({ height = 26, label = true }: { height?: number; label?: boolean }) {
  return (
    <div className="sec4-sig" title="A Sec4data solution">
      {label && <span className="sig-by">by</span>}
      <img src={sec4dataLogo} alt="Sec4data — Cyber Defense" style={{ height }} />
    </div>
  );
}
