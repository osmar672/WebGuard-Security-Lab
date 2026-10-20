import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity, ArrowRight, Bot, BrainCircuit, CheckCircle2, ChevronRight, CircleDot, Clock3, Database,
  FileBarChart2, Gauge, History, Radio, RefreshCw, ShieldAlert, ShieldCheck, Target,
} from 'lucide-react';
import { loadDashboardSnapshot, type DashboardSnapshot, type Resource } from '../api/dashboardService';
import { apiBaseUrl, apiPaths } from '../api/config';
import { MetricCard } from '../components/MetricCard';
import { ResourceState } from '../components/ResourceState';
import { StatusPill } from '../components/StatusPill';

const loadingResource = <T,>(): Resource<T> => ({ kind: 'loading' });
const initialSnapshot: DashboardSnapshot = {
  backendHealth: loadingResource(),
  databaseHealth: loadingResource(),
  targetCount: loadingResource(),
  auditCount: loadingResource(),
  recentJobs: loadingResource(),
  engineStatuses: loadingResource(),
  recentActivity: loadingResource(),
};

const endpointCount = Object.values(apiPaths).filter(Boolean).length;
const totalEndpoints = Object.keys(apiPaths).length;

function resourceStatus(resource: Resource<{ status: string }>): { text: string; tone: 'success' | 'warning' | 'danger' | 'neutral' } {
  if (resource.kind === 'loaded') {
    const value = resource.data.status.toLowerCase();
    if (['healthy', 'ok', 'operational', 'available'].includes(value)) return { text: resource.data.status, tone: 'success' };
    if (['degraded', 'warning'].includes(value)) return { text: resource.data.status, tone: 'warning' };
    return { text: resource.data.status, tone: 'danger' };
  }
  if (resource.kind === 'error') return { text: 'Error', tone: 'danger' };
  if (resource.kind === 'loading') return { text: 'Checking', tone: 'neutral' };
  return { text: 'Not configured', tone: 'neutral' };
}

function resourceMetric<T>(resource: Resource<T>, formatter: (data: T) => string): string {
  if (resource.kind === 'loaded') return formatter(resource.data);
  if (resource.kind === 'error') return 'Error';
  return '—';
}

function displayDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

const shortcutItems = [
  { label: 'Targets', description: 'Review registered targets and scope', path: '/targets', icon: Target, color: 'mint' },
  { label: 'AI Copilot', description: 'Prioritize findings and improve workflows', path: '/ai-assistant', icon: BrainCircuit, color: 'mint' },
  { label: 'Security scanner', description: 'View scanner availability', path: '/scanner', icon: ShieldCheck, color: 'violet' },
  { label: 'Browser bots', description: 'Controlled browser automation', path: '/browser-bots', icon: Bot, color: 'blue' },
  { label: 'Load tests', description: 'Bounded performance testing', path: '/load-tests', icon: Gauge, color: 'amber' },
  { label: 'Reports', description: 'Review generated reports', path: '/reports', icon: FileBarChart2, color: 'rose' },
  { label: 'Audit history', description: 'Trace recorded activity', path: '/history', icon: History, color: 'slate' },
];

export function DashboardPage() {
  const [snapshot, setSnapshot] = useState(initialSnapshot);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    const result = await loadDashboardSnapshot();
    setSnapshot(result);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    let active = true;
    void loadDashboardSnapshot().then((result) => { if (active) setSnapshot(result); });
    return () => { active = false; };
  }, []);

  const backend = resourceStatus(snapshot.backendHealth);
  const database = resourceStatus(snapshot.databaseHealth);
  const jobsResource = snapshot.recentJobs;
  const enginesResource = snapshot.engineStatuses;
  const activityResource = snapshot.recentActivity;

  return (
    <div className="dashboard-page">
      <section className="integration-banner" aria-label="Integration status">
        <div className="integration-banner__symbol"><ShieldAlert size={20} aria-hidden="true" /></div>
        <div className="integration-banner__copy">
          <strong>{snapshot.backendHealth.kind === 'loaded' ? 'Backend connected' : snapshot.backendHealth.kind === 'error' ? 'Backend connection unavailable' : 'Connecting to WebGuard API'}</strong>
          <p>{snapshot.backendHealth.kind === 'loaded' ? `Live health response received at ${displayDate(snapshot.backendHealth.data.checked_at ?? '')}. Dashboard values below are read from the current backend contract.` : snapshot.backendHealth.kind === 'error' ? snapshot.backendHealth.message : 'Checking the configured local API. Metrics remain blank until the backend returns valid data.'}</p>
        </div>
        <Link to="/settings" className="text-link">Review setup <ArrowRight size={15} aria-hidden="true" /></Link>
      </section>

      <div className="section-heading section-heading--metrics">
        <div><h2>System pulse</h2><p>Values are loaded from the configured backend only.</p></div>
        <button type="button" className="quiet-button" onClick={() => void refresh()} disabled={refreshing}>
          <RefreshCw size={15} className={refreshing ? 'spin' : ''} aria-hidden="true" />{refreshing ? 'Refreshing' : 'Refresh data'}
        </button>
      </div>

      <section className="metric-grid" aria-label="System metrics">
        <MetricCard label="Backend health" value="" kind="status" status={backend.text} tone={backend.tone} description={snapshot.backendHealth.kind === 'loaded' ? 'Live API response' : 'Awaiting configured endpoint'} icon={<Activity size={18} />} />
        <MetricCard label="Database" value="" kind="status" status={database.text} tone={database.tone} description={snapshot.databaseHealth.kind === 'loaded' ? 'Live API response' : 'Awaiting configured endpoint'} icon={<Database size={18} />} />
        <MetricCard label="Targets" value={resourceMetric(snapshot.targetCount, String)} description={snapshot.targetCount.kind === 'loaded' ? 'Reported by backend' : 'No count available'} icon={<Target size={18} />} />
        <MetricCard label="Audits" value={resourceMetric(snapshot.auditCount, String)} description={snapshot.auditCount.kind === 'loaded' ? 'Reported by backend' : 'No count available'} icon={<ClipboardIcon />} />
      </section>

      <section className="overview-grid">
        <article className="panel panel--recent-jobs">
          <div className="panel__heading"><div><h2>Recent audits</h2><p>Most recent audit records returned by the backend.</p></div><Link className="icon-link" to="/history" aria-label="Open history"><ChevronRight size={18} /></Link></div>
          <ResourceState resource={jobsResource} emptyTitle="No audits yet" emptyDescription="The backend returned an empty audit list. No activity is being fabricated.">
            {(jobs) => <div className="jobs-table-wrap"><table className="jobs-table"><thead><tr><th>Audit</th><th>State</th><th>Created</th></tr></thead><tbody>{jobs.map((job) => <tr key={job.id}><td><span className="job-name"><span className="job-name__icon"><CircleDot size={15} /></span><span><strong>{job.name}</strong><small>#{job.id}</small></span></span></td><td><StatusPill status={job.status} /></td><td className="muted-cell">{displayDate(job.created_at)}</td></tr>)}</tbody></table></div>}
          </ResourceState>
          <div className="panel__footer"><span>{jobsResource.kind === 'loaded' ? `${jobsResource.data.length} audit(s) returned` : 'Audit endpoint status shown above'}</span><Link to="/scanner" className="text-link">View modules <ArrowRight size={14} /></Link></div>
        </article>

        <article className="panel panel--engines">
          <div className="panel__heading"><div><h2>Engine status</h2><p>Read-only status from configured services.</p></div><span className="panel__heading-icon"><ShieldCheck size={17} /></span></div>
          <ResourceState resource={enginesResource} emptyTitle="No engines reported" emptyDescription="An empty engine list was returned by the backend.">
            {(engines) => <div className="engine-list">{engines.map((engine) => <div className="engine-row" key={engine.name}><span className="engine-row__symbol"><CheckCircle2 size={17} /></span><div className="engine-row__copy"><strong>{engine.name}</strong><small>{engine.message ?? 'Status reported by backend'}</small></div><StatusPill status={engine.status} /></div>)}</div>}
          </ResourceState>
          <p className="panel__note"><span className="small-dot" />No scanner, browser bot, or load test is started from this dashboard.</p>
        </article>
      </section>

      <section className="overview-grid overview-grid--lower">
        <article className="panel panel--activity">
          <div className="panel__heading"><div><h2>Recent activity</h2><p>Event-level activity feed is reserved for a later backend phase.</p></div><Link to="/history" className="text-link">View history <ArrowRight size={14} /></Link></div>
          <ResourceState resource={activityResource} emptyTitle="No activity available" emptyDescription="No audit events have been returned for this view.">
            {(events) => <div className="activity-list">{events.map((event) => <div className="activity-row" key={event.id}><div className="activity-row__icon"><Clock3 size={16} /></div><div className="activity-row__copy"><strong>{event.action}</strong><small>{event.actor ? `${event.actor} · ` : ''}{displayDate(event.created_at)}</small></div></div>)}</div>}
          </ResourceState>
        </article>
        <article className="panel panel--setup">
          <div className="panel__heading"><div><h2>Connection status</h2><p>Frontend integration configuration.</p></div><span className="panel__heading-icon"><Radio size={17} /></span></div>
          <div className="setup-list">
            <div><span>API base URL</span><strong className="setup-list__value">{apiBaseUrl || 'Not set'}</strong></div>
            <div><span>Configured endpoint paths</span><strong>{endpointCount} / {totalEndpoints}</strong></div>
            <div><span>Backend connection</span><StatusPill status={snapshot.backendHealth.kind === 'loaded' ? 'Connected' : snapshot.backendHealth.kind === 'error' ? 'Unavailable' : 'Checking'} /></div>
          </div>
          <Link to="/settings" className="setup-link">Complete integration setup <ArrowRight size={15} /></Link>
        </article>
      </section>

      <section className="shortcuts-section">
        <div className="section-heading"><div><h2>Module shortcuts</h2><p>Open a workspace. Modules that are not implemented remain clearly marked.</p></div></div>
        <div className="shortcut-grid">{shortcutItems.map(({ label, description, path, icon: Icon, color }) => <Link to={path} className="shortcut-card" key={path}><span className={`shortcut-card__icon shortcut-card__icon--${color}`}><Icon size={19} aria-hidden="true" /></span><span className="shortcut-card__copy"><strong>{label}</strong><small>{description}</small></span><ArrowRight className="shortcut-card__arrow" size={16} aria-hidden="true" /></Link>)}</div>
      </section>
    </div>
  );
}

function ClipboardIcon() {
  return <Activity size={18} aria-hidden="true" />;
}
