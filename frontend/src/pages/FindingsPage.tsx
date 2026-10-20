import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, ShieldAlert } from 'lucide-react';
import { loadFindings, type FindingRecord } from '../api/recordService';
import { EmptyState } from '../components/EmptyState';
import { StatusPill } from '../components/StatusPill';

export function FindingsPage() {
  const [rows, setRows] = useState<FindingRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [severity, setSeverity] = useState('all');
  const refresh = useCallback(async () => {
    setRefreshing(true);
    try { const result = await loadFindings(); setRows(result.data); setError(''); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to load findings.'); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);
  const visible = severity === 'all' ? rows : rows.filter((row) => row.severity === severity);
  return <div className="records-page">
    <section className="module-status-banner"><div className="module-status-banner__icon"><ShieldAlert size={20} /></div><div className="module-status-banner__copy"><strong>Findings from the backend only</strong><p>WebGuard does not create sample findings or treat unimplemented engines as successful scans.</p></div><StatusPill status="Read only" /></section>
    <section className="panel record-list-panel">
      <div className="panel__heading"><div><h2>Security findings</h2><p>{rows.length} records returned by the current API.</p></div><button className="icon-button" onClick={() => void refresh()} disabled={refreshing} aria-label="Refresh findings"><RefreshCw size={16} className={refreshing ? 'spin' : ''} /></button></div>
      <div className="record-filters"><label htmlFor="finding-severity">Severity</label><select id="finding-severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select></div>
      {loading ? <div className="skeleton-line" aria-label="Loading findings" /> : error ? <EmptyState compact title="Could not load findings" description={error} /> : visible.length === 0 ? <EmptyState title="No findings recorded" description="No findings match this filter. This is an empty result, not proof that a target is secure." /> : <div className="table-scroll"><table className="records-table"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead><tbody>{visible.map((finding) => <tr key={finding.id}><td><div className="record-primary"><span><strong>{finding.title}</strong><small>{finding.url || `Audit ${finding.audit_id}`}</small></span></div>{finding.description && <p className="record-description">{finding.description}</p>}</td><td><StatusPill status={finding.severity} tone={finding.severity === 'critical' || finding.severity === 'high' ? 'danger' : finding.severity === 'medium' ? 'warning' : 'neutral'} /></td><td><StatusPill status={finding.status} /></td><td>{new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(finding.created_at))}</td></tr>)}</tbody></table></div>}
    </section>
  </div>;
}
