import { useCallback, useEffect, useState } from 'react';
import { History, RefreshCw } from 'lucide-react';
import { loadHistoryEvents, type HistoryEvent } from '../api/toolService';
import { EmptyState } from '../components/EmptyState';
import { StatusPill } from '../components/StatusPill';

const dateLabel = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
};
export function HistoryPage() {
  const [rows, setRows] = useState<HistoryEvent[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const refresh = useCallback(async () => {
    setRefreshing(true);
    try { const result = await loadHistoryEvents(); setRows(result.data); setTotal(result.total); setError(''); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to load event history.'); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);
  return <div className="records-page">
    <section className="module-status-banner"><div className="module-status-banner__icon"><History size={20} /></div><div className="module-status-banner__copy"><strong>Security audit events</strong><p>Persisted activity from target authorization, queued jobs, tool execution and report operations.</p></div><StatusPill status={total == null ? `${rows.length} loaded` : `${total} events`} /></section>
    <section className="panel record-list-panel">
      <div className="panel__heading"><div><h2>Recent activity</h2><p>Newest audit events first. Payloads contain operational metadata, not tool console output.</p></div><button className="icon-button" onClick={() => void refresh()} disabled={refreshing} aria-label="Refresh audit history"><RefreshCw size={16} className={refreshing ? 'spin' : ''} /></button></div>
      {loading ? <div className="skeleton-line" aria-label="Loading audit history" /> : error ? <EmptyState compact title="Could not load history" description={error} /> : rows.length === 0 ? <EmptyState title="No events yet" description="Authorization changes and tool executions will appear here after activity occurs." /> : <div className="table-scroll"><table className="records-table"><thead><tr><th>Event</th><th>Entity</th><th>Details</th><th>Time</th></tr></thead><tbody>{rows.map((event) => <tr key={event.id}><td><strong>{event.event_type}</strong><small className="table-subtext">{event.id}</small></td><td><span>{event.entity_type}</span><small className="table-subtext"><code>{event.entity_id}</code></small></td><td><pre className="history-payload">{JSON.stringify(event.payload, null, 2)}</pre></td><td>{dateLabel(event.created_at)}</td></tr>)}</tbody></table></div>}
    </section>
  </div>;
}
