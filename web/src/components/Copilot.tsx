import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { Icon } from './icons';
import { copilotBus } from './copilotBus';

interface Msg { role: 'user' | 'assistant'; content: string; }

const QUICK = [
  { label: 'Explain critical alert', q: 'Explain the most recent critical alert and its business risk.' },
  { label: 'Generate hunting query', q: 'Generate a threat hunting query (Sigma + Wazuh) to detect lateral movement via RDP.' },
  { label: 'Summarize incident', q: 'Summarize incident INC-2026-0481 and outline the next containment steps.' },
  { label: 'Suggest response', q: 'Suggest a response playbook for a suspected ransomware case on a Windows endpoint.' },
];

const GREETING = `### Hi, I'm the **SOC Copilot** 🛡️
I'm connected to the full Sec4data stack. Current posture **ELEVATED**, **8 active incidents** — the most critical is **INC-2026-0481** (suspected ransomware on FIN-WS-014).

I can help you:
- Explain and triage alerts
- Investigate and correlate entities
- Generate **threat hunting** queries
- Suggest **response playbooks**

Where should I start?`;

function mdToHtml(md: string): string {
  let h = md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/```([\s\S]*?)```/g, (_m, c) => `<pre>${c.trim()}</pre>`)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^###\s*(.+)$/gm, '<h4>$1</h4>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/^[-•]\s*(.+)$/gm, '<li>$1</li>');
  h = h.replace(/(<li>[\s\S]*?<\/li>)/g, (m) => `<ul>${m}</ul>`).replace(/<\/ul>\s*<ul>/g, '');
  return h.split(/\n{2,}/).map((p) => /^<(h4|ul|pre)/.test(p.trim()) ? p : `<p>${p.replace(/\n/g, '<br>')}</p>`).join('');
}

export function Copilot({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [greeted, setGreeted] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);
  const history = useRef<Msg[]>([]);

  useEffect(() => {
    if (open && !greeted) {
      setMsgs([{ role: 'assistant', content: GREETING }]);
      setGreeted(true);
    }
  }, [open, greeted]);

  useEffect(() => { bodyRef.current?.scrollTo(0, bodyRef.current.scrollHeight); }, [msgs, busy]);

  useEffect(() => copilotBus.subscribe((text) => { void send(text); }), []);

  async function send(text: string) {
    const t = text.trim();
    if (!t || busy) return;
    setInput('');
    const userMsg: Msg = { role: 'user', content: t };
    history.current.push(userMsg);
    setMsgs((m) => [...m, userMsg]);
    setBusy(true);
    try {
      const { reply } = await api.copilot(history.current.slice(-8));
      const botMsg: Msg = { role: 'assistant', content: reply };
      history.current.push(botMsg);
      setMsgs((m) => [...m, botMsg]);
    } catch {
      setMsgs((m) => [...m, { role: 'assistant', content: 'Could not reach the Copilot service. Check the backend.' }]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <aside className={`copilot ${open ? 'open' : ''}`}>
      <div className="cp-head">
        <div className="cp-ava"><Icon.cpu size={21} /><span className="live" /></div>
        <div className="cp-ti">
          <div className="n">SOC Copilot <span className="v">AI</span></div>
          <div className="s">Analysis · Investigation · Hunting · Response</div>
        </div>
        <button className="cp-close" onClick={onClose}><Icon.close /></button>
      </div>

      <div className="cp-body" ref={bodyRef}>
        {msgs.map((m, i) => (
          <div key={i} className={`msg ${m.role === 'user' ? 'user' : 'bot'}`}>
            <div className="m-ava">{m.role === 'user' ? 'SA' : 'AI'}</div>
            {m.role === 'user'
              ? <div className="m-body">{m.content}</div>
              : <div className="m-body" dangerouslySetInnerHTML={{ __html: mdToHtml(m.content) }} />}
          </div>
        ))}
        {busy && (
          <div className="msg bot">
            <div className="m-ava">AI</div>
            <div className="m-body"><div className="typing"><i /><i /><i /></div></div>
          </div>
        )}
      </div>

      <div className="cp-quick">
        {QUICK.map((q) => <button key={q.label} className="q" onClick={() => send(q.q)}>{q.label}</button>)}
      </div>

      <div className="cp-input">
        <textarea
          rows={1} value={input} placeholder="Ask the Copilot about events, IOCs, hunting, response..."
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void send(input); } }}
        />
        <button className="cp-send" disabled={busy} onClick={() => void send(input)}><Icon.send /></button>
      </div>
    </aside>
  );
}
