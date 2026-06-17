import type { ReactNode } from 'react';

type P = { size?: number };
const S = (size: number, children: ReactNode) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.9}>{children}</svg>
);

export const Icon = {
  logout: ({ size = 16 }: P) => S(size, <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="m16 17 5-5-5-5M21 12H9" /></>),
  dashboard: ({ size = 21 }: P) => S(size, <><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></>),
  pulse: ({ size = 15 }: P) => S(size, <path d="M22 12h-4l-3 9L9 3l-3 9H2" />),
  shield: ({ size = 19 }: P) => S(size, <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />),
  alert: ({ size = 21 }: P) => S(size, <><path d="m21.7 13.4-9-9a2 2 0 0 0-2.8 0l-7 7a2 2 0 0 0 0 2.8l9 9c.8.8 2 .8 2.8 0l7-7a2 2 0 0 0 0-2.8Z" /><path d="M12 8v4M12 16h.01" /></>),
  search: ({ size = 21 }: P) => S(size, <><circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3M11 8v6M8 11h6" /></>),
  hunt: ({ size = 21 }: P) => S(size, <><path d="M12 2 2 7l10 5 10-5-10-5Z" /><path d="m2 17 10 5 10-5M2 12l10 5 10-5" /></>),
  bolt: ({ size = 21 }: P) => S(size, <path d="M13 2 3 14h7l-1 8 10-12h-7l1-8Z" />),
  grid: ({ size = 21 }: P) => S(size, <><rect x="2" y="2" width="9" height="9" rx="1" /><rect x="13" y="2" width="9" height="9" rx="1" /><rect x="2" y="13" width="9" height="9" rx="1" /><rect x="13" y="13" width="9" height="9" rx="1" /></>),
  cpu: ({ size = 21 }: P) => S(size, <><path d="M12 2a4 4 0 0 1 4 4c0 1-.4 1.9-1 2.6 1.8.9 3 2.8 3 4.9V18a3 3 0 0 1-3 3H9a3 3 0 0 1-3-3v-4.5c0-2.1 1.2-4 3-4.9-.6-.7-1-1.6-1-2.6a4 4 0 0 1 4-4Z" /><path d="M9 14h.01M15 14h.01" /></>),
  cog: ({ size = 21 }: P) => S(size, <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.9 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V22a2 2 0 0 1-4 0v-.2A1.6 1.6 0 0 0 6.6 20l-.1.1a2 2 0 1 1-2.8-2.9l.1-.1A1.6 1.6 0 0 0 2 14.4H2a2 2 0 0 1 0-4h.2A1.6 1.6 0 0 0 4 6.6L3.9 6.5a2 2 0 1 1 2.9-2.8l.1.1A1.6 1.6 0 0 0 9.6 2H10a2 2 0 0 1 4 0v.2a1.6 1.6 0 0 0 2.7 1.1l.1-.1a2 2 0 1 1 2.8 2.9l-.1.1A1.6 1.6 0 0 0 22 9.6V10a2 2 0 0 1 0 4h-.2a1.6 1.6 0 0 0-1.4 1Z" /></>),
  bell: ({ size = 18 }: P) => S(size, <><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" /><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" /></>),
  spark: ({ size = 15 }: P) => S(size, <path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8" />),
  download: ({ size = 14 }: P) => S(size, <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />),
  layers: ({ size = 15 }: P) => S(size, <path d="m12 2 9 5-9 5-9-5 9-5ZM3 12l9 5 9-5M3 17l9 5 9-5" />),
  plug: ({ size = 15 }: P) => S(size, <path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0V8ZM12 17v5" />),
  globe: ({ size = 15 }: P) => S(size, <><circle cx="12" cy="12" r="10" /><path d="M2 12h20M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20" /></>),
  plus: ({ size = 14 }: P) => S(size, <path d="M12 5v14M5 12h14" />),
  clock: ({ size = 13 }: P) => S(size, <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>),
  target: ({ size = 15 }: P) => S(size, <><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1" /></>),
  intel: ({ size = 15 }: P) => S(size, <><circle cx="12" cy="12" r="10" /><path d="M2 12h20M12 2a15 15 0 0 1 0 20" /></>),
  save: ({ size = 14 }: P) => S(size, <><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2Z" /><path d="M17 21v-8H7v8M7 3v5h8" /></>),
  play: ({ size = 14 }: P) => S(size, <path d="m6 3 14 9-14 9V3Z" />),
  case: ({ size = 14 }: P) => S(size, <><rect x="2" y="7" width="20" height="14" rx="2" /><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2" /></>),
  host: ({ size = 16 }: P) => S(size, <><rect x="3" y="4" width="18" height="12" rx="1" /><path d="M7 20h10M9 16v4M15 16v4" /></>),
  ip: ({ size = 16 }: P) => S(size, <><circle cx="12" cy="12" r="10" /><path d="M2 12h20M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20" /></>),
  user: ({ size = 16 }: P) => S(size, <><circle cx="12" cy="8" r="4" /><path d="M6 21v-1a6 6 0 0 1 12 0v1" /></>),
  file: ({ size = 16 }: P) => S(size, <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" /><path d="M14 2v6h6" /></>),
  fire: ({ size = 19 }: P) => S(size, <path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.4-.5-2-1-3-1.07-2.14-.5-4 .5-5.5 1.6 2.5 3.5 3 5 5 1.5 2 1 4 1 4.5a4.5 4.5 0 0 1-9 0c0-1 .5-2 1.5-3" />),
  radar: ({ size = 19 }: P) => S(size, <><path d="M19.07 4.93A10 10 0 0 0 6.99 3.34" /><path d="M4 6h.01M2.29 9.62a10 10 0 1 0 18.94 13.34" /><path d="M16 9a5 5 0 0 0-8 0M12 12v.01" /></>),
  edr: ({ size = 19 }: P) => S(size, <><rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4" /></>),
  ids: ({ size = 19 }: P) => S(size, <path d="M3 12h4l3 8 4-16 3 8h4" />),
  block: ({ size = 22 }: P) => S(size, <><circle cx="12" cy="12" r="10" /><path d="m4.9 4.9 14.2 14.2" /></>),
  isolate: ({ size = 22 }: P) => S(size, <><rect x="3" y="4" width="18" height="12" rx="1" /><path d="M7 20h10" /><path d="m15 9-3 3-1.5-1.5" /></>),
  disable: ({ size = 22 }: P) => S(size, <><circle cx="9" cy="8" r="4" /><path d="M3 21v-1a6 6 0 0 1 9-5" /><path d="m17 14 5 5M22 14l-5 5" /></>),
  quarantine: ({ size = 22 }: P) => S(size, <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" /><path d="M12 11v5M9.5 13.5h5" /></>),
  key: ({ size = 22 }: P) => S(size, <><circle cx="7.5" cy="15.5" r="4.5" /><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14 9l2 2" /></>),
  send: ({ size = 19 }: P) => S(size, <path d="m22 2-7 20-4-9-9-4 20-7Z" />),
  close: ({ size = 16 }: P) => S(size, <path d="M18 6 6 18M6 6l12 12" />),
};

export const integrationIcon: Record<string, (p: P) => ReactNode> = {
  wazuh: Icon.shield, opnsense: Icon.fire, malcolm: Icon.radar, velociraptor: Icon.edr,
  misp: Icon.intel, thehive: Icon.case, suricata: Icon.ids, graylog: Icon.file,
  'firewall-syslog': Icon.fire,
  webhook: Icon.plug,
};
