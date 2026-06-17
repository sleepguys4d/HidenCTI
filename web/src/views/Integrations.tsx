import { useEffect, useMemo, useState } from 'react';
import { api, type ConnectorSpec, type ConnectorField, type TestResult } from '../api';
import { PageHead, Btn, Icon } from '../components/ui';
import { integrationIcon } from '../components/icons';
import { toast } from '../components/toast';

type Draft = { enabled: boolean; fields: Record<string, string | boolean> };

export function Integrations() {
  const [list, setList] = useState<ConnectorSpec[]>([]);
  const [mode, setMode] = useState('demo');
  const [editing, setEditing] = useState<ConnectorSpec | null>(null);
  const [testing, setTesting] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, TestResult>>({});

  const load = () => api.connectors().then((r) => { setList(r.data); setMode(r.mode); }).catch(() => {});
  useEffect(() => { load(); }, []);

  const toggle = async (c: ConnectorSpec, enabled: boolean) => {
    setList((prev) => prev.map((x) => (x.key === c.key ? { ...x, enabled } : x)));
    try { await api.enableConnector(c.key, enabled); } finally { load(); }
  };

  const runTest = async (c: ConnectorSpec) => {
    setTesting((t) => ({ ...t, [c.key]: true }));
    setResults((r) => ({ ...r, [c.key]: undefined as unknown as TestResult }));
    try { const res = await api.testConnector(c.key); setResults((r) => ({ ...r, [c.key]: res })); }
    catch { setResults((r) => ({ ...r, [c.key]: { ok: false, state: 'off', message: 'Failed to reach the server.' } })); }
    finally { setTesting((t) => ({ ...t, [c.key]: false })); }
  };

  const configured = list.filter((c) => c.configured).length;
  const enabled = list.filter((c) => c.enabled).length;

  return (
    <>
      <PageHead title="Integrations" sub={`Configure and enable each integration here — no file editing · ${mode.toUpperCase()} mode · ${enabled} active · ${configured} configured`}
        actions={<Btn onClick={load}><Icon.pulse size={15} /> Refresh</Btn>} />

      <div className="conn-grid">
        {list.map((c) => {
          const Ico = integrationIcon[c.key] || Icon.shield;
          const res = results[c.key];
          return (
            <div className="conn" key={c.key}>
              <div className="top">
                <div className="ci">{Ico({})}</div>
                <div className="cmeta"><div className="cn">{c.label}</div><div className="cc">{c.category}</div></div>
                <span className={`sdot ${c.enabled ? (c.configured || c.push ? 'on' : 'deg') : 'off'}`} style={{ marginTop: 6 }} />
              </div>

              <div className="badges">
                {c.push && <span className="cbadge push">Push</span>}
                {c.pull && <span className="cbadge">Collection</span>}
                <span className={`cbadge ${c.configured ? 'ok' : 'warn'}`}>{c.configured ? 'Configured' : 'Not configured'}</span>
                <span className="cbadge src">{c.source === 'db' ? 'DB' : c.source === 'memory' ? 'Memory' : '.env'}</span>
              </div>

              {res && (
                <div className={`testbar ${res.ok ? 'ok' : res.state === 'deg' ? 'warn' : 'fail'}`}>
                  <span>{res.ok ? '✓' : res.state === 'deg' ? '!' : '✕'}</span><span>{res.message}</span>
                </div>
              )}
              {testing[c.key] && <div className="testbar warn"><span className="sp" />Testing connection…</div>}

              <div className="actions">
                <label className="switch" title={c.enabled ? 'Enabled' : 'Disabled'}>
                  <input type="checkbox" checked={c.enabled} onChange={(e) => toggle(c, e.target.checked)} />
                  <span className="track" />
                  <span className="lbl">{c.enabled ? 'Active' : 'Inactive'}</span>
                </label>
                <span className="grow" />
                {c.testable && <button className="mini" onClick={() => runTest(c)} disabled={testing[c.key]}>Test</button>}
                <button className="mini cfg" onClick={() => setEditing(c)}>Configure</button>
              </div>
            </div>
          );
        })}
      </div>

      {editing && (
        <ConnectorModal spec={editing} onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); toast(`${editing.label} saved`); load(); }} />
      )}
    </>
  );
}

function ConnectorModal({ spec, onClose, onSaved }: { spec: ConnectorSpec; onClose: () => void; onSaved: () => void }) {
  const Ico = integrationIcon[spec.key] || Icon.shield;
  const init = useMemo<Draft>(() => {
    const fields: Record<string, string | boolean> = {};
    for (const f of spec.fields) fields[f.name] = f.type === 'bool' ? Boolean(f.value) : (f.secret ? '' : String(f.value ?? ''));
    return { enabled: spec.enabled, fields };
  }, [spec]);
  const [draft, setDraft] = useState<Draft>(init);
  const [saving, setSaving] = useState(false);

  const set = (name: string, v: string | boolean) => setDraft((d) => ({ ...d, fields: { ...d.fields, [name]: v } }));

  const missing = spec.fields.filter((f) => f.required && f.type !== 'bool' && !String(draft.fields[f.name] || '') && !(f.secret && f.isSet));

  const save = async () => {
    setSaving(true);
    try { await api.saveConnector(spec.key, { enabled: draft.enabled, fields: draft.fields }); onSaved(); }
    finally { setSaving(false); }
  };

  return (
    <div className="modal-ov" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="mhead">
          <div className="ci">{Ico({})}</div>
          <div><div className="t">{spec.label}</div><div className="s">{spec.category}</div></div>
          <button className="x" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="mbody">
          {spec.fields.map((f: ConnectorField) => f.type === 'bool' ? (
            <div className="field bool" key={f.name}>
              <label htmlFor={f.name}>{f.label}</label>
              <label className="switch">
                <input id={f.name} type="checkbox" checked={Boolean(draft.fields[f.name])} onChange={(e) => set(f.name, e.target.checked)} />
                <span className="track" />
              </label>
            </div>
          ) : (
            <div className="field" key={f.name}>
              <label htmlFor={f.name}>{f.label}{f.required && <span className="req">*</span>}</label>
              <input id={f.name} type={f.type === 'password' ? 'password' : f.type === 'url' ? 'url' : 'text'}
                value={String(draft.fields[f.name] ?? '')}
                placeholder={f.secret && f.isSet ? '•••••••• (set — leave blank to keep)' : f.placeholder || ''}
                onChange={(e) => set(f.name, e.target.value)} autoComplete="off" />
              {f.help && <div className="help">{f.help}</div>}
            </div>
          ))}
        </div>
        <div className="mfoot">
          <label className="switch" style={{ gap: 10 }}>
            <input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))} />
            <span className="track" />
            <span className="lbl">{draft.enabled ? 'Enable on save' : 'Keep inactive'}</span>
          </label>
          <span className="grow" />
          <button className="mini" onClick={onClose}>Cancel</button>
          <Btn primary onClick={save}>{saving ? 'Saving…' : missing.length ? `${missing.length} field(s) missing` : 'Save'}</Btn>
        </div>
      </div>
    </div>
  );
}
