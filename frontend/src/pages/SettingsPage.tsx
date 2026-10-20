import { CheckCircle2, CircleAlert, ExternalLink, FileCode2, ShieldCheck } from 'lucide-react';
import { apiBaseUrl, apiPaths, isValidApiBaseUrl } from '../api/config';
import { StatusPill } from '../components/StatusPill';

const endpointLabels: Array<{ key: keyof typeof apiPaths; label: string; note: string }> = [
  { key: 'health', label: 'Backend and database health', note: 'Implemented in current backend' },
  { key: 'dashboardSummary', label: 'Dashboard summary', note: 'Implemented in current backend' },
  { key: 'engines', label: 'Engine status', note: 'Implemented; engines may be unconfigured' },
  { key: 'targets', label: 'Targets', note: 'Implemented in current backend' },
  { key: 'audits', label: 'Audits', note: 'Implemented in current backend' },
  { key: 'findings', label: 'Findings', note: 'Implemented in current backend' },
  { key: 'aiStatus', label: 'AI Copilot status', note: 'Authenticated; reports local or configured remote mode' },
  { key: 'aiAssist', label: 'AI-assisted workflows', note: 'Authenticated, rate-limited and advisory-only' },
  { key: 'auditHistory', label: 'Audit history', note: 'Uses the documented audits endpoint' },
  { key: 'recentActivity', label: 'Recent activity events', note: 'Reserved for a later phase' },
  { key: 'scannerJobs', label: 'Scanner jobs', note: 'Reserved for a later phase' },
  { key: 'browserBots', label: 'Browser bots', note: 'Reserved for a later phase' },
  { key: 'loadTests', label: 'Load tests', note: 'Reserved for a later phase' },
  { key: 'reports', label: 'Reports', note: 'Reserved for a later phase' },
];

export function SettingsPage() {
  const baseUrlValid = isValidApiBaseUrl(apiBaseUrl);
  const implemented = endpointLabels.filter(({ key }) => Boolean(apiPaths[key])).length;

  return (
    <div className="settings-page">
      <section className="integration-banner integration-banner--settings">
        <div className="integration-banner__symbol"><FileCode2 size={20} /></div>
        <div className="integration-banner__copy">
          <strong>Using the current WebGuard API contract</strong>
          <p>Existing FastAPI routes are configured centrally. Routes reserved for later phases remain disabled rather than being invented.</p>
        </div>
      </section>

      <section className="panel settings-panel">
        <div className="panel__heading"><div><h2>API connection</h2><p>The optional base URL is read from the frontend environment; blank uses the current origin.</p></div><span className="panel__heading-icon"><ShieldCheck size={18} /></span></div>
        <div className="settings-connection-row"><div><span className="settings-field-label">API base URL</span><code>{apiBaseUrl || 'Same origin (recommended)'}</code></div><StatusPill status={baseUrlValid ? 'Configured' : 'Not configured'} /></div>
        <div className="settings-connection-row"><div><span className="settings-field-label">Implemented routes</span><strong>{implemented} of {endpointLabels.length} displayed routes</strong></div><StatusPill status={implemented ? 'Connected by configuration' : 'Not configured'} /></div>
        <p className="settings-note"><CircleAlert size={16} aria-hidden="true" /> Frontend environment variables are public at build time. Never put API keys, passwords, tokens, or other secrets in a <code>VITE_*</code> variable.</p>
      </section>

      <section className="panel endpoint-panel">
        <div className="panel__heading"><div><h2>Endpoint configuration</h2><p>Available paths come from <code>docs/API_CONTRACT.md</code>.</p></div><span className="endpoint-count">{implemented}/{endpointLabels.length}</span></div>
        <div className="endpoint-list">
          {endpointLabels.map(({ key, label, note }) => {
            const value = apiPaths[key];
            return <div className="endpoint-row" key={key}>
              <div className="endpoint-row__state">{value ? <CheckCircle2 size={17} /> : <CircleAlert size={17} />}</div>
              <div className="endpoint-row__copy"><strong>{label}</strong><small>{note}</small></div>
              <div className="endpoint-row__value">{value || 'Not implemented'}</div>
              <StatusPill status={value ? 'Configured' : 'Coming soon'} />
            </div>;
          })}
        </div>
      </section>

      <section className="panel settings-panel">
        <div className="panel__heading"><div><h2>AI Copilot privacy</h2><p>AI requests are handled on the backend and never need a frontend API key.</p></div><span className="panel__heading-icon"><ShieldCheck size={18} /></span></div>
        <p className="settings-note"><CircleAlert size={16} aria-hidden="true" /> Remote model use sends minimized assessment context to the configured provider. Common credential patterns are redacted, but this is best-effort and cannot guarantee removal of every secret. Without a key, the deterministic local assistant remains available.</p>
        <p className="small-muted">Para usar Groq, configura <code>WEBGUARD_AI_API_KEY</code>, <code>WEBGUARD_AI_MODEL</code> y <code>WEBGUARD_AI_BASE_URL</code> en el entorno del backend. Consulta <code>docs/AI_COPILOT.md</code>.</p>
      </section>

      <section className="panel settings-doc-panel"><div className="settings-doc-icon"><FileCode2 size={21} /></div><div><h3>How to change the API address</h3><p>Copy <code>frontend/.env.example</code> to <code>frontend/.env.local</code>, change <code>VITE_API_BASE_URL</code>, then restart Vite.</p><p className="small-muted">Only route paths already present in the backend are enabled. No API credentials belong in frontend variables.</p></div><a href="https://vite.dev/guide/env-and-mode" target="_blank" rel="noreferrer" className="external-doc-link">Vite env docs <ExternalLink size={14} /></a></section>
    </div>
  );
}
