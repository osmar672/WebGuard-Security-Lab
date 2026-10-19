import { CheckCircle2, CircleAlert, ExternalLink, FileCode2, ShieldCheck } from 'lucide-react';
import { apiBaseUrl, apiPaths, isValidApiBaseUrl } from '../api/config';
import { StatusPill } from '../components/StatusPill';

const endpointLabels: Array<{ key: keyof typeof apiPaths; label: string; env: string }> = [
  { key: 'health', label: 'Backend health', env: 'VITE_API_HEALTH_PATH' },
  { key: 'databaseHealth', label: 'Database health', env: 'VITE_API_DATABASE_HEALTH_PATH' },
  { key: 'targetsCount', label: 'Target count', env: 'VITE_API_TARGETS_COUNT_PATH' },
  { key: 'auditsCount', label: 'Audit count', env: 'VITE_API_AUDITS_COUNT_PATH' },
  { key: 'recentJobs', label: 'Recent executions', env: 'VITE_API_RECENT_JOBS_PATH' },
  { key: 'engineStatus', label: 'Engine status', env: 'VITE_API_ENGINE_STATUS_PATH' },
  { key: 'recentActivity', label: 'Recent activity', env: 'VITE_API_RECENT_ACTIVITY_PATH' },
  { key: 'targets', label: 'Targets module', env: 'VITE_API_TARGETS_PATH' },
  { key: 'scannerJobs', label: 'Scanner jobs', env: 'VITE_API_SCANNER_JOBS_PATH' },
  { key: 'browserBots', label: 'Browser bots', env: 'VITE_API_BROWSER_BOTS_PATH' },
  { key: 'loadTests', label: 'Load tests', env: 'VITE_API_LOAD_TESTS_PATH' },
  { key: 'findings', label: 'Findings', env: 'VITE_API_FINDINGS_PATH' },
  { key: 'reports', label: 'Reports', env: 'VITE_API_REPORTS_PATH' },
  { key: 'auditHistory', label: 'Audit history', env: 'VITE_API_AUDIT_HISTORY_PATH' },
];

export function SettingsPage() {
  const baseUrlValid = isValidApiBaseUrl(apiBaseUrl);
  const configured = endpointLabels.filter(({ key }) => Boolean(apiPaths[key])).length;

  return (
    <div className="settings-page">
      <section className="integration-banner integration-banner--settings">
        <div className="integration-banner__symbol"><FileCode2 size={20} /></div>
        <div className="integration-banner__copy"><strong>API routes are placeholders by design</strong><p>The supplied Phase 0 file lists the contract requirements but does not include an actual API_CONTRACT.md. Do not fill these values using guessed routes. Ask the backend owner for approved paths and DTO schemas first.</p></div>
      </section>

      <section className="panel settings-panel">
        <div className="panel__heading"><div><h2>API connection</h2><p>Connection details come from environment variables.</p></div><span className="panel__heading-icon"><ShieldCheck size={18} /></span></div>
        <div className="settings-connection-row"><div><span className="settings-field-label">API base URL</span><code>{apiBaseUrl || 'Not set'}</code></div><StatusPill status={baseUrlValid ? 'Configured' : 'Not configured'} /></div>
        <div className="settings-connection-row"><div><span className="settings-field-label">Endpoint paths</span><strong>{configured} of {endpointLabels.length} configured</strong></div><StatusPill status={configured === endpointLabels.length ? 'Configured' : 'Incomplete'} /></div>
        <p className="settings-note"><CircleAlert size={16} aria-hidden="true" /> Frontend environment variables are public at build time. Never put API keys, passwords, tokens, or other secrets in a <code>VITE_*</code> variable.</p>
      </section>

      <section className="panel endpoint-panel">
        <div className="panel__heading"><div><h2>Endpoint configuration</h2><p>Each route remains disabled until its official path is supplied.</p></div><span className="endpoint-count">{configured}/{endpointLabels.length}</span></div>
        <div className="endpoint-list">
          {endpointLabels.map(({ key, label, env }) => {
            const value = apiPaths[key];
            return <div className="endpoint-row" key={key}><div className="endpoint-row__state">{value ? <CheckCircle2 size={17} /> : <CircleAlert size={17} />}</div><div className="endpoint-row__copy"><strong>{label}</strong><code>{env}</code></div><div className="endpoint-row__value">{value || 'Not configured'}</div><StatusPill status={value ? 'Configured' : 'Pending'} /></div>;
          })}
        </div>
      </section>

      <section className="panel settings-doc-panel"><div className="settings-doc-icon"><FileCode2 size={21} /></div><div><h3>How to configure</h3><p>Copy <code>.env.example</code> to <code>.env.local</code>, then add only backend-approved relative paths. Restart the Vite server after editing environment variables.</p><p className="small-muted">Frontend schemas are marked as placeholders in <code>src/api/dashboardService.ts</code>. Align them to the backend contract before enabling real data.</p></div><a href="https://vite.dev/guide/env-and-mode" target="_blank" rel="noreferrer" className="external-doc-link">Vite env docs <ExternalLink size={14} /></a></section>
    </div>
  );
}
