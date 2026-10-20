import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Plus, RefreshCw, ShieldCheck, Target } from 'lucide-react';
import { createTarget, loadTargets, type TargetRecord } from '../api/recordService';
import { authorizeTarget, revokeTarget } from '../api/toolService';
import { getSessionUser } from '../api/session';
import { EmptyState } from '../components/EmptyState';
import { StatusPill } from '../components/StatusPill';

function prettyDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(parsed);
}

export function TargetsPage() {
  const [targets, setTargets] = useState<TargetRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [formError, setFormError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('https://');
  const [authorizationNote, setAuthorizationNote] = useState('');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const role = getSessionUser()?.role;
  const canCreate = role === 'admin' || role === 'operator';

  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      const result = await loadTargets();
      setTargets(result.data);
      setLoadError('');
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : 'Unable to load targets.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  async function changeAuthorization(target: TargetRecord) {
    setFormError(''); setNotice('');
    try {
      if (target.authorization_status === 'authorized') {
        if (!window.confirm(`Revoke authorization for ${target.name}? Queued and running jobs will be cancelled.`)) return;
        await revokeTarget(target.id);
        setNotice(`Authorization revoked for ${target.name}.`);
      } else {
        const reference = window.prompt('Enter the approval reference / reason (at least 8 characters). This is stored in the audit log.');
        if (reference === null) return;
        if (reference.trim().length < 8) throw new Error('The authorization note must have at least 8 characters.');
        await authorizeTarget(target.id, reference.trim());
        setNotice(`Authorization activated for ${target.name}.`);
      }
      await refresh();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : 'Could not update target authorization.');
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError('');
    setNotice('');
    setBusy(true);
    try {
      const url = new URL(baseUrl.trim());
      if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Use an HTTP or HTTPS address.');
      if (url.username || url.password || url.search || url.hash) throw new Error('Remove URL credentials, query parameters, and fragments.');
      await createTarget({
        name: name.trim(), base_url: url.toString(), authorization_confirmed: true,
        authorization_note: authorizationNote.trim() || null,
      });
      setName('');
      setBaseUrl('https://');
      setAuthorizationNote('');
      setAuthorizationConfirmed(false);
      setNotice('Target registered. Its authorization remains unverified until the backend workflow validates it.');
      await refresh();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : 'Target registration failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="records-page">
      <section className="module-status-banner">
        <div className="module-status-banner__icon"><ShieldCheck size={20} aria-hidden="true" /></div>
        <div className="module-status-banner__copy">
          <strong>Server-side target validation is enabled</strong>
          <p>Register only systems you own or are explicitly authorized to assess. Registration does not start a scan or mark the target as verified.</p>
        </div>
        <StatusPill status="Authorized use only" />
      </section>

      {canCreate && <section className="panel record-create-panel">
        <div className="panel__heading"><div><h2>Register a target</h2><p>Each new target is assigned to your signed-in account.</p></div><span className="panel__heading-icon"><Plus size={18} /></span></div>
        <form className="record-form" onSubmit={submit}>
          <label htmlFor="target-name">Display name</label>
          <input id="target-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={120} placeholder="Company website" />
          <label htmlFor="target-url">Base URL</label>
          <input id="target-url" type="url" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} required maxLength={2048} placeholder="https://example.com/" />
          <label htmlFor="authorization-note">Authorization evidence / internal note (optional)</label>
          <textarea id="authorization-note" value={authorizationNote} onChange={(event) => setAuthorizationNote(event.target.value)} maxLength={2000} rows={2} placeholder="Owner, ticket, approval reference, and expiry details" />
          <label className="authorization-checkbox"><input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} required /> I confirm I own this target or have explicit permission to assess it.</label>
          {formError && <p className="form-message form-message--error" role="alert">{formError}</p>}
          {notice && <p className="form-message form-message--success" role="status">{notice}</p>}
          <button className="primary-action" type="submit" disabled={busy || !authorizationConfirmed}><Plus size={16} /> {busy ? 'Registering…' : 'Register target'}</button>
        </form>
      </section>}
      {!canCreate && <section className="panel"><EmptyState compact title="Read-only role" description="Your account can view its assigned targets, but an operator or administrator must register new targets." /></section>}

      <section className="panel record-list-panel">
        <div className="panel__heading"><div><h2>Registered targets</h2><p>Targets assigned to your account or visible to the administrator.</p></div><button className="icon-button" onClick={() => void refresh()} disabled={refreshing} aria-label="Refresh targets" title="Refresh targets"><RefreshCw size={16} className={refreshing ? 'spin' : ''} /></button></div>
        {loading ? <div className="skeleton-line" aria-label="Loading targets" /> : loadError ? <EmptyState title="Could not load targets" description={loadError} compact /> : targets.length === 0 ? <EmptyState title="No targets registered" description="Register an authorized target to establish its scope. This step does not execute a scan." /> : (
          <div className="table-scroll"><table className="records-table"><thead><tr><th>Target</th><th>Authorization</th><th>Environment</th><th>Created</th></tr></thead>
            <tbody>{targets.map((target) => <tr key={target.id}>
              <td><div className="record-primary"><span className="record-icon"><Target size={16} /></span><span><strong>{target.name}</strong><small>{target.base_url}</small></span></div></td>
              <td><div className="target-authorization-cell"><StatusPill status={target.authorization_status} />{canCreate && <button className="secondary-button" type="button" onClick={() => void changeAuthorization(target)}>{target.authorization_status === 'authorized' ? 'Revoke' : 'Authorize'}</button>}</div></td>
              <td><StatusPill status={target.is_lab_target ? 'Isolated lab' : 'Public target'} tone={target.is_lab_target ? 'warning' : 'neutral'} /></td>
              <td>{prettyDate(target.created_at)}</td>
            </tr>)}</tbody>
          </table></div>
        )}
      </section>
    </div>
  );
}
