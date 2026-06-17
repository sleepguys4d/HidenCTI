import axios from 'axios';
import { config, connectorConfigured } from '../config.js';

const SYSTEM = `You are the SOC Xpert Copilot, the AI assistant of Sec4data's unified security platform (Sec4data is an Angolan cybersecurity company, sec4data.com).

Your role is to support SOC analysts across the full cycle: alert triage, incident investigation, threat hunting and response. You ALWAYS reply in English, in a technical, concise and actionable way, like a senior SOC analyst.

Operational context (the platform integrates Wazuh SIEM, OPNsense Firewall, Malcolm/Zeek NDR, Velociraptor EDR, MISP Threat Intel, TheHive/Cortex SOAR, Suricata IDS). Current posture ELEVATED. Critical incident in progress INC-2026-0481: suspected ransomware (likely LockBit 3.0) on workstation FIN-WS-014, user j.matamba, C2 185.220.101.34 (Tor), binary svchost_2.exe, lateral movement via RDP, shadow copies deleted.

Capabilities to demonstrate: explain alerts and map them to MITRE ATT&CK; generate hunting queries (Sigma, Wazuh QL, KQL) in fenced code blocks; summarise incidents and propose containment/eradication/recovery; suggest response playbooks. Use ### headings, lists and fenced code blocks. Be direct and operational. Do not claim you executed actions — propose them.`;

interface ChatMessage { role: 'user' | 'assistant'; content: string; }

export async function copilotChat(messages: ChatMessage[]): Promise<{ reply: string; live: boolean }> {
  if (connectorConfigured.anthropic()) {
    try {
      const { data } = await axios.post(
        'https://api.anthropic.com/v1/messages',
        { model: config.anthropic.model, max_tokens: 1024, system: SYSTEM, messages: messages.slice(-10) },
        {
          headers: {
            'x-api-key': config.anthropic.apiKey,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json',
          },
          timeout: 40000,
        },
      );
      const reply = (data.content || []).map((c: any) => (c.type === 'text' ? c.text : '')).join('\n').trim();
      if (reply) return { reply, live: true };
    } catch (err) {
      console.warn('[copilot] Anthropic unavailable, using fallback —', (err as Error).message);
    }
  }
  return { reply: fallback(messages[messages.length - 1]?.content || ''), live: false };
}

function fallback(q: string): string {
  const l = q.toLowerCase();
  if (l.includes('hunting') || l.includes('query') || l.includes('lateral') || l.includes('dns')) {
    return `### Threat hunting query
Proposed in **Sigma** + **Wazuh QL**:
\`\`\`yaml
title: RDP lateral movement + credential access
logsource: { product: windows, service: security }
detection:
  rdp_logon: { EventID: 4624, LogonType: 10 }
  lsass_access: { EventID: 4656, ObjectName|endswith: lsass.exe }
  timeframe: 10m
  condition: rdp_logon and lsass_access
level: high
\`\`\`
**Next step:** run it against the data lake and promote hits to an incident.`;
  }
  if (l.includes('incident') || l.includes('0481') || l.includes('summar')) {
    return `### Summary · INC-2026-0481
**Severity:** Critical · **Host:** FIN-WS-014 · **User:** j.matamba

Chain: T1110 (SSH bruteforce) -> T1210 (SMB) -> T1003 (LSASS) -> T1021 (RDP) -> T1071 (C2 Tor) -> T1490 (shadow copies deleted).

### Next steps
- Isolate FIN-WS-014 (keep the EDR channel)
- Block 185.220.101.34 and 45.137.21.8
- Disable j.matamba, quarantine svchost_2.exe
- Validate offline backups before restoring`;
  }
  if (l.includes('response') || l.includes('ransomware') || l.includes('playbook')) {
    return `### Playbook — Ransomware (Windows endpoint)
1. **Isolate** the endpoint via EDR while keeping telemetry.
2. **Contain** — block C2/IPs on the firewall + DNS sinkhole.
3. **Identify** the family via MISP and the lateral reach.
4. **Eradicate** — kill the process, quarantine the binary, remove persistence.
5. **Credentials** — forced reset + secret rotation.
6. **Recover** — restore from a validated offline backup.`;
  }
  return `Understood. With the current context I can **explain** an alert (MITRE), **generate** a hunting query, **summarise** an incident or **suggest** a response playbook. Give me the host, IOC or incident.

*(Real-time AI in fallback mode — set ANTHROPIC_API_KEY for full responses.)*`;
}
