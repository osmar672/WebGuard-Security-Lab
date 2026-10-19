import { ArrowRight, LockKeyhole, Wrench } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { apiPaths } from '../api/config';
import { EmptyState } from '../components/EmptyState';
import { StatusPill } from '../components/StatusPill';

interface ModuleDetails {
  title: string;
  eyebrow: string;
  state: 'contract' | 'coming-soon';
  endpointKey?: keyof typeof apiPaths;
  summary: string;
  requirements: string[];
}

const moduleDetails: Record<string, ModuleDetails> = {
  '/targets': {
    title: 'Authorized targets', eyebrow: 'Workspace / Targets', state: 'contract', endpointKey: 'targets',
    summary: 'Only targets with server-side authorization and scope records may be used by assessment jobs.',
    requirements: ['Approved target response schema', 'Server-side scope and authorization checks', 'Explicit isolated-lab configuration for local targets'],
  },
  '/scanner': {
    title: 'Security scanner', eyebrow: 'Operations / Security scanner', state: 'coming-soon', endpointKey: 'scannerJobs',
    summary: 'The dashboard can show scanner jobs once the backend API and scanner engine are integrated.',
    requirements: ['Server-side scope validation before every job', 'Shared job states: pending, queued, running, completed, failed, cancelled', 'Progress events from the backend'],
  },
  '/browser-bots': {
    title: 'Browser bots', eyebrow: 'Operations / Browser bots', state: 'coming-soon', endpointKey: 'browserBots',
    summary: 'Browser automation is not started by this frontend placeholder.',
    requirements: ['Playwright worker integration', 'Network-level egress restrictions', 'Scope validation for navigation and redirects'],
  },
  '/load-tests': {
    title: 'Load tests', eyebrow: 'Operations / Load tests', state: 'coming-soon', endpointKey: 'loadTests',
    summary: 'Load generation remains disabled until the authorized backend execution flow exists.',
    requirements: ['k6 runner integration', 'Explicit limits for concurrency, duration, and request volume', 'Server-side authorization immediately before execution'],
  },
  '/findings': {
    title: 'Findings', eyebrow: 'Insights / Findings', state: 'contract', endpointKey: 'findings',
    summary: 'Findings will be displayed only from validated backend responses; the UI does not invent or seed findings.',
    requirements: ['Approved Finding model and response schema', 'Pagination and filter parameters from API contract', 'Severity and status enums from the backend contract'],
  },
  '/reports': {
    title: 'Reports', eyebrow: 'Insights / Reports', state: 'contract', endpointKey: 'reports',
    summary: 'Report listing and download actions require the official API paths and access rules.',
    requirements: ['Approved Report model and response schema', 'Authorized report download endpoint', 'Error and empty-state behavior from the shared contract'],
  },
  '/history': {
    title: 'Audit history', eyebrow: 'Insights / History', state: 'contract', endpointKey: 'auditHistory',
    summary: 'This page will show backend audit events and execution history when the endpoints are configured.',
    requirements: ['Approved AuditEvent schema', 'Stable identifiers and timestamps', 'Server-side access controls for audit records'],
  },
};

export function ModulePage() {
  const location = useLocation();
  const details = moduleDetails[location.pathname];
  if (!details) return null;

  const endpoint = details.endpointKey ? apiPaths[details.endpointKey] : '';
  const comingSoon = details.state === 'coming-soon';

  return (
    <div className="module-page">
      <section className="module-status-banner">
        <div className="module-status-banner__icon">{comingSoon ? <Wrench size={20} /> : <LockKeyhole size={20} />}</div>
        <div className="module-status-banner__copy"><strong>{comingSoon ? 'Module not connected' : 'Backend contract required'}</strong><p>{comingSoon ? 'This module is a navigation and integration placeholder. It does not run scans, browser actions, or load generation.' : 'The provided architecture brief does not include the approved API paths and response schema for this resource.'}</p></div>
        <StatusPill status={comingSoon ? 'Coming soon' : endpoint ? 'Path configured' : 'Not configured'} />
      </section>

      <section className="panel module-overview">
        <div className="module-overview__top"><span className="module-overview__symbol"><LockKeyhole size={22} /></span><StatusPill status={comingSoon ? 'Disabled' : endpoint ? 'Endpoint configured' : 'Not configured'} /></div>
        <h2>{details.title}</h2>
        <p className="module-overview__summary">{details.summary}</p>
        <div className="module-overview__divider" />
        <h3>Integration checklist</h3>
        <ul className="checklist">{details.requirements.map((requirement) => <li key={requirement}><span className="checklist__marker" />{requirement}</li>)}</ul>
        <div className="module-endpoint"><span>Endpoint path</span><code>{endpoint || 'Not configured in .env'}</code></div>
        <Link className="primary-link" to="/settings">Review integration settings <ArrowRight size={16} /></Link>
      </section>

      <section className="panel module-empty">
        <EmptyState title={comingSoon ? 'No actions available' : 'No records loaded'} description={comingSoon ? 'The module remains intentionally inactive until its backend worker and safety checks are implemented.' : 'No API call has been made because the exact endpoint or response schema is not yet approved. This prevents fabricated data and accidental contract drift.'} />
      </section>
    </div>
  );
}
