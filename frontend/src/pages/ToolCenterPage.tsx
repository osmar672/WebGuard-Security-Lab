import { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, Clock3, Code2, Play, RefreshCw, ShieldCheck, Square, Wrench } from 'lucide-react';
import { Link } from 'react-router-dom';
import { loadTargets, type TargetRecord } from '../api/recordService';
import { cancelToolRun, cancelWorkspaceRun, createToolRun, createWorkspaceRun, loadToolCatalog, loadToolRuns, loadWorkspaceRuns,
  type RunState, type ToolCatalogItem, type ToolProfile, type ToolRun, type WorkspaceRun } from '../api/toolService';
import { getSessionUser } from '../api/session';
import { EmptyState } from '../components/EmptyState';
import { StatusPill } from '../components/StatusPill';

const categoryLabel: Record<string, string> = {
  web_security: 'Web security', api_testing: 'API testing', browser: 'Browser automation',
  performance: 'Performance', code_security: 'Code and supply chain', configuration: 'Configuration checks',
};
const stateLabel: Record<ToolCatalogItem['state'], string> = {
  available: 'Available', disabled: 'Disabled by policy', not_configured: 'Not configured',
  not_implemented: 'Not implemented', unavailable: 'Unavailable',
};
const busyStates: RunState[] = ['queued', 'running', 'pending'];
const dateText = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
};

export function ToolCenterPage({ category }: { category?: string }) {
  const [tools, setTools] = useState<ToolCatalogItem[]>([]);
  const [targets, setTargets] = useState<TargetRecord[]>([]);
  const [runs, setRuns] = useState<ToolRun[]>([]);
  const [workspaceRuns, setWorkspaceRuns] = useState<WorkspaceRun[]>([]);
  const [targetId, setTargetId] = useState('');
  const [profile, setProfile] = useState<ToolProfile>('quick');
  const [selectedTool, setSelectedTool] = useState('http_headers');
  const [confirmAuthorization, setConfirmAuthorization] = useState(false);
  const [confirmWorkspace, setConfirmWorkspace] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const user = getSessionUser();
  const isAdmin = user?.role === 'admin';

  const refresh = useCallback(async (quiet = false) => {
    if (!quiet) setRefreshing(true);
    try {
      const [catalog, targetPage, targetRuns] = await Promise.all([loadToolCatalog(), loadTargets(), loadToolRuns()]);
      setTools(catalog);
      setTargets(targetPage.data);
      setRuns(targetRuns);
      if (isAdmin) {
        try { setWorkspaceRuns(await loadWorkspaceRuns()); } catch { setWorkspaceRuns([]); }
      }
      setError('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load tools and run history.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(true), 4000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const filteredTools = useMemo(() => tools.filter((tool) => {
    if (!category) return true;
    if (category === 'web_security') return ['web_security', 'api_testing', 'configuration'].includes(tool.category) && tool.id !== 'reports';
    return tool.category === category;
  }), [tools, category]);
  const selectedDefinition = filteredTools.find((tool) => tool.id === selectedTool) ?? filteredTools[0];
  const authorizedTargets = targets.filter((target) => target.authorization_status === 'authorized');
  const visibleRuns = category ? runs.filter((run) => {
    const tool = tools.find((item) => item.id === run.engine);
    if (category === 'web_security') return Boolean(tool && ['web_security', 'api_testing', 'configuration'].includes(tool.category) && tool.id !== 'reports');
    return tool?.category === category;
  }) : runs;
  const visibleWorkspaceRuns = category && category !== 'code_security' ? [] : workspaceRuns;

  async function runTargetTool() {
    if (!selectedDefinition || !selectedDefinition.requires_target || !targetId) return;
    setError(''); setNotice(''); setBusy(true);
    try {
      const run = await createToolRun({ engine: selectedDefinition.id, target_id: targetId, profile, authorization_confirmed: true });
      setNotice(`Queued ${selectedDefinition.name}. Run ID: ${run.id}`);
      setConfirmAuthorization(false);
      await refresh(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not queue tool run.');
    } finally { setBusy(false); }
  }

  async function runWorkspaceTool(tool: ToolCatalogItem) {
    if (!isAdmin || !confirmWorkspace) return;
    setError(''); setNotice(''); setBusy(true);
    try {
      const run = await createWorkspaceRun({ engine: tool.id as 'trivy' | 'semgrep' | 'gitleaks' | 'sbom', profile, authorization_confirmed: true });
      setNotice(`Queued ${tool.name}. Run ID: ${run.id}`);
      setConfirmWorkspace(false);
      await refresh(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not queue workspace scan.');
    } finally { setBusy(false); }
  }

  async function cancel(runId: string, workspace = false) {
    setError(''); setNotice('');
    try {
      if (workspace) await cancelWorkspaceRun(runId); else await cancelToolRun(runId);
      setNotice(`Cancellation requested for run ${runId}.`);
      await refresh(true);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not cancel run.'); }
  }

  const title = category ? ({ web_security: 'Security Scanner', browser: 'Browser Bots', performance: 'Load Tests', code_security: 'Code Security' }[category] ?? 'Tool Center') : 'Tool Center';
  return <div className="records-page tool-center-page">
    <section className="module-status-banner">
      <div className="module-status-banner__icon"><Wrench size={20} aria-hidden="true" /></div>
      <div className="module-status-banner__copy"><strong>{title} · Real engine registry</strong><p>Choose from installed engines, queue bounded jobs and inspect normalized results. A tool is not shown as usable unless its server-side dependencies and policy are configured.</p></div>
      <StatusPill status={`${tools.filter((tool) => tool.state === 'available').length} available`} />
    </section>
    {error && <p className="form-message form-message--error" role="alert">{error}</p>}
    {notice && <p className="form-message form-message--success" role="status">{notice}</p>}

    <div className="tool-center-layout">
      <section className="panel tool-launch-panel">
        <div className="panel__heading"><div><h2>Launch a test</h2><p>Run only against explicitly authorized scope.</p></div><span className="panel__heading-icon"><Play size={18} /></span></div>
        {loading ? <div className="skeleton-line" aria-label="Loading tools" /> : filteredTools.length === 0 ? <EmptyState title="No tools in this category" description="Choose another tool category from the navigation." compact /> : <form className="tool-launch-form" onSubmit={(event) => { event.preventDefault(); void runTargetTool(); }}>
          <label htmlFor="tool-select">Test engine</label>
          <select id="tool-select" value={selectedDefinition?.id ?? ''} onChange={(event) => { setSelectedTool(event.target.value); setConfirmWorkspace(false); }}>
            {filteredTools.map((tool) => <option key={tool.id} value={tool.id}>{tool.name} · {stateLabel[tool.state]}</option>)}
          </select>
          {selectedDefinition && <div className="tool-selected-detail"><StatusPill status={stateLabel[selectedDefinition.state]} tone={selectedDefinition.state === 'available' ? 'success' : 'neutral'} /><p>{selectedDefinition.description}</p><small>{selectedDefinition.detail}</small></div>}
          <label htmlFor="tool-profile">Test profile</label>
          <select id="tool-profile" value={profile} onChange={(event) => setProfile(event.target.value as ToolProfile)}>
            <option value="quick">Quick · lowest impact</option><option value="standard">Standard · bounded</option><option value="exhaustive">Exhaustive · stricter time allowance</option>
          </select>
          {selectedDefinition?.requires_target ? <>
            <label htmlFor="tool-target">Authorized target</label>
            <select id="tool-target" value={targetId} onChange={(event) => { setTargetId(event.target.value); setConfirmAuthorization(false); }} required>
              <option value="">Select a target</option>
              {targets.map((target) => <option key={target.id} value={target.id}>{target.name} · {target.authorization_status}</option>)}
            </select>
            {targetId && targets.find((target) => target.id === targetId)?.authorization_status !== 'authorized' && <p className="tool-warning"><AlertTriangle size={15} /> This target is not authorized for execution yet. Open <Link to="/targets">Targets</Link> and explicitly authorize it.</p>}
            <label className="authorization-checkbox"><input type="checkbox" checked={confirmAuthorization} onChange={(event) => setConfirmAuthorization(event.target.checked)} required /> I am authorized to test this target and confirm this run is within scope.</label>
            <button className="primary-button" type="submit" disabled={busy || selectedDefinition?.state !== 'available' || !authorizedTargets.some((target) => target.id === targetId) || !confirmAuthorization}><Play size={16} /> {busy ? 'Queueing…' : 'Queue test'}</button>
          </> : selectedDefinition?.id === 'reports' ? <div className="tool-reports-link"><p>Reports are available for completed runs.</p><Link to="/reports">Open Reports & Regression</Link></div> : (['trivy', 'semgrep', 'gitleaks', 'sbom'].includes(selectedDefinition?.id ?? '') && isAdmin) ? <>
            <p className="tool-warning"><Code2 size={15} /> This scans the server-configured source directory, not a user-supplied path. Check <code>WEBGUARD_WORKSPACE_SCAN_ROOT</code> first.</p>
            <label className="authorization-checkbox"><input type="checkbox" checked={confirmWorkspace} onChange={(event) => setConfirmWorkspace(event.target.checked)} required /> I am authorized to scan the configured code workspace.</label>
            <button type="button" className="primary-button" disabled={busy || selectedDefinition?.state !== 'available' || !confirmWorkspace} onClick={() => selectedDefinition && void runWorkspaceTool(selectedDefinition)}><Play size={16} /> {busy ? 'Queueing…' : 'Queue workspace scan'}</button>
          </> : <p className="tool-setup-help">This capability does not start a network job from this screen. Follow the configuration status above.</p>}
        </form>}
        <div className="tool-safe-note"><ShieldCheck size={17} /><p>WebGuard revalidates saved target scope before queueing. External engines remain disabled until the server operator explicitly confirms deployment-level egress filtering.</p></div>
      </section>

      <section className="panel tool-catalog-panel">
        <div className="panel__heading"><div><h2>Installed tools</h2><p>Availability comes from server configuration, not from frontend guesses.</p></div><button className="icon-button" onClick={() => void refresh()} disabled={refreshing} aria-label="Refresh tools"><RefreshCw size={16} className={refreshing ? 'spin' : ''} /></button></div>
        {loading ? <div className="skeleton-line" aria-label="Loading tool catalog" /> : <div className="tool-grid">{filteredTools.map((tool) => <article className="tool-card" key={tool.id}>
          <div className="tool-card__top"><span className="tool-card__icon"><Wrench size={16} /></span><StatusPill status={stateLabel[tool.state]} tone={tool.state === 'available' ? 'success' : 'neutral'} /></div>
          <h3>{tool.name}</h3><span className="tool-card__category">{categoryLabel[tool.category]}</span><p>{tool.description}</p><small>{tool.detail}</small>
          <button type="button" className="secondary-button" onClick={() => { setSelectedTool(tool.id); document.getElementById('tool-select')?.focus(); }} disabled={tool.state !== 'available'}>Configure this test</button>
        </article>)}</div>}
      </section>
    </div>

    <section className="panel tool-runs-panel">
      <div className="panel__heading"><div><h2>Recent target runs</h2><p>Queue state and findings from actual engine output.</p></div><Activity size={19} /></div>
      {visibleRuns.length === 0 ? <EmptyState title="No target runs yet" description="Queue an available test above. Jobs are persisted and processed by the separate WebGuard worker." /> : <div className="tool-run-list">{visibleRuns.map((run) => <article className="tool-run-row" key={run.id}>
        <div className="tool-run-row__main"><span className="tool-run-row__icon"><Activity size={16} /></span><div><strong>{run.target_name} · {run.engine}</strong><small>{dateText(run.created_at)} · {run.profile} profile · {run.results.finding_count ?? run.results.findings?.length ?? 0} findings</small><code>{run.id}</code></div></div>
        <div className="tool-run-row__status"><StatusPill status={run.state} /><div className={`tool-progress${run.state === 'running' ? ' tool-progress--indeterminate' : ''}`} aria-label={run.state === 'running' ? 'Engine is running; live percentage is not provided' : `${run.progress}% complete`}><span style={run.state === 'running' ? undefined : { width: `${Math.max(0, Math.min(100, run.progress))}%` }} /></div><small>{run.state === 'running' ? 'Running' : `${run.progress}%`}</small></div>
        <div className="tool-run-row__actions">{busyStates.includes(run.state) && <button className="icon-button" title="Cancel run" aria-label={`Cancel ${run.engine} run`} onClick={() => void cancel(run.id)}><Square size={15} /></button>}<details><summary>Details</summary><pre>{JSON.stringify({ summary: run.results.summary, findings: run.results.findings, notes: run.results.notes, error: run.error_message }, null, 2)}</pre></details></div>
      </article>)}</div>}
    </section>

    {(visibleWorkspaceRuns.length > 0 || (category == null && isAdmin)) && <section className="panel tool-runs-panel">
      <div className="panel__heading"><div><h2>Source workspace scans</h2><p>Trivy, Semgrep, Gitleaks and CycloneDX SBOM generation run only against the server-configured workspace.</p></div><Code2 size={19} /></div>
      {visibleWorkspaceRuns.length === 0 ? <EmptyState title="No source scans yet" description="Configure WEBGUARD_WORKSPACE_SCAN_ROOT and enable the code-security engines before starting a source scan." /> : <div className="tool-run-list">{visibleWorkspaceRuns.map((run) => <article className="tool-run-row" key={run.id}>
        <div className="tool-run-row__main"><span className="tool-run-row__icon"><Code2 size={16} /></span><div><strong>{run.engine} · source workspace</strong><small>{dateText(run.created_at)} · {run.profile} profile · {run.results.finding_count ?? run.results.findings?.length ?? 0} findings</small><code>{run.id}</code></div></div>
        <div className="tool-run-row__status"><StatusPill status={run.state} /><div className={`tool-progress${run.state === 'running' ? ' tool-progress--indeterminate' : ''}`} aria-label={run.state === 'running' ? 'Engine is running; live percentage is not provided' : `${run.progress}% complete`}><span style={run.state === 'running' ? undefined : { width: `${Math.max(0, Math.min(100, run.progress))}%` }} /></div><small>{run.state === 'running' ? 'Running' : `${run.progress}%`}</small></div>
        <div className="tool-run-row__actions">{busyStates.includes(run.state) && <button className="icon-button" title="Cancel source scan" aria-label={`Cancel ${run.engine} source scan`} onClick={() => void cancel(run.id, true)}><Square size={15} /></button>}<details><summary>Details</summary><pre>{JSON.stringify({ summary: run.results.summary, findings: run.results.findings, notes: run.results.notes, error: run.error_message }, null, 2)}</pre></details></div>
      </article>)}</div>}
    </section>}

    <div className="tool-center-footnote"><Clock3 size={15} /><span>Profiles are bounded server-side. A job marked available only means its configured dependency exists; individual assessments may fail due to network policy, target responses, missing rule databases or tool-specific setup.</span></div>
  </div>;
}
