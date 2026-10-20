import { useCallback, useEffect, useMemo, useState } from 'react';
import { Download, FileChartColumn, GitCompareArrows, RefreshCw, ShieldAlert } from 'lucide-react';
import { loadAudits, type AuditRecord } from '../api/recordService';
import { compareAudits, downloadReport, loadWorkspaceRuns, type RegressionReport, type WorkspaceRun } from '../api/toolService';
import { EmptyState } from '../components/EmptyState';
import { StatusPill } from '../components/StatusPill';
import { getSessionUser } from '../api/session';

export function ReportsPage() {
  const [audits, setAudits] = useState<AuditRecord[]>([]);
  const [workspaceRuns, setWorkspaceRuns] = useState<WorkspaceRun[]>([]);
  const [currentAudit, setCurrentAudit] = useState('');
  const [baselineAudit, setBaselineAudit] = useState('');
  const [regression, setRegression] = useState<RegressionReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const isAdmin = getSessionUser()?.role === 'admin';

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const auditResult = await loadAudits();
      setAudits(auditResult.data);
      if (isAdmin) {
        try { setWorkspaceRuns(await loadWorkspaceRuns()); } catch { setWorkspaceRuns([]); }
      }
      setCurrentAudit((old) => old && auditResult.data.some((a) => a.id === old) ? old : auditResult.data.find((a) => a.state === 'completed')?.id ?? '');
      setBaselineAudit((old) => old && auditResult.data.some((a) => a.id === old) ? old : auditResult.data.find((a) => a.state === 'completed')?.id ?? '');
      setError('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load report sources.');
    } finally { setLoading(false); }
  }, [isAdmin]);
  useEffect(() => { void refresh(); }, [refresh]);

  const completedAudits = useMemo(() => audits.filter((audit) => audit.state === 'completed'), [audits]);
  const completedWorkspaceRuns = useMemo(() => workspaceRuns.filter((run) => run.state === 'completed'), [workspaceRuns]);
  const selectedCurrent = completedAudits.find((audit) => audit.id === currentAudit);
  const selectedBaseline = completedAudits.find((audit) => audit.id === baselineAudit);

  async function exportAudit(auditId: string, format: 'json' | 'html' | 'pdf' | 'sarif') {
    setBusy(true); setError(''); setNotice('');
    try { await downloadReport({ auditId, format }); setNotice(`${format.toUpperCase()} report downloaded.`); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Report export failed.'); }
    finally { setBusy(false); }
  }
  async function exportWorkspace(scan: WorkspaceRun, format: 'json' | 'html' | 'pdf' | 'sarif' | 'cyclonedx') {
    setBusy(true); setError(''); setNotice('');
    try { await downloadReport({ workspaceScanId: scan.id, format }); setNotice(`${format.toUpperCase()} report downloaded.`); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Report export failed.'); }
    finally { setBusy(false); }
  }
  async function runComparison() {
    if (!currentAudit || !baselineAudit || currentAudit === baselineAudit) return;
    setBusy(true); setError(''); setNotice(''); setRegression(null);
    try { setRegression(await compareAudits(currentAudit, baselineAudit)); setNotice('Comparison completed.'); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Comparison failed.'); }
    finally { setBusy(false); }
  }

  const auditFormats = ['json', 'html', 'pdf', 'sarif'] as const;
  const workspaceFormats = ['json', 'html', 'pdf', 'sarif'] as const;
  return <div className="records-page reports-page">
    <section className="module-status-banner"><div className="module-status-banner__icon"><FileChartColumn size={20} /></div><div className="module-status-banner__copy"><strong>Reports & security regression</strong><p>Export stored engine results, share machine-readable findings, and compare completed audits. This page never invents report data.</p></div><StatusPill status="Stored results only" /></section>
    {error && <p className="form-message form-message--error" role="alert">{error}</p>}
    {notice && <p className="form-message form-message--success" role="status">{notice}</p>}

    <section className="panel reports-source-panel">
      <div className="panel__heading"><div><h2>Target audit reports</h2><p>JSON for archiving, HTML for reading, SARIF for compatible security tooling.</p></div><button className="icon-button" onClick={() => void refresh()} disabled={loading} aria-label="Refresh report sources"><RefreshCw size={16} /></button></div>
      {loading ? <div className="skeleton-line" aria-label="Loading report sources" /> : completedAudits.length === 0 ? <EmptyState title="No completed audits" description="Reports will become available after an authorized test job has finished and results have been stored." /> : <div className="report-source-list">{completedAudits.map((audit) => <article className="report-source-row" key={audit.id}>
        <div className="report-source-row__identity"><span className="tool-run-row__icon"><FileChartColumn size={16} /></span><div><strong>{audit.name}</strong><small>Completed {new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(audit.finished_at ?? audit.created_at))}</small><code>{audit.id}</code></div></div>
        <StatusPill status={audit.state} />
        <div className="report-export-actions">{auditFormats.map((format) => <button key={format} className="secondary-button" onClick={() => void exportAudit(audit.id, format)} disabled={busy}><Download size={14} /> {format.toUpperCase()}</button>)}</div>
      </article>)}</div>}
    </section>

    <section className="panel reports-source-panel">
      <div className="panel__heading"><div><h2>Regression comparison</h2><p>Match the same target across two completed audits.</p></div><GitCompareArrows size={19} /></div>
      {completedAudits.length < 2 ? <EmptyState compact title="Two completed audits are required" description="Run the same authorized checks again after applying a fix; WebGuard will compare stored findings." /> : <div className="report-compare-controls">
        <div><label htmlFor="current-audit">Current audit</label><select id="current-audit" value={currentAudit} onChange={(event) => { setCurrentAudit(event.target.value); setRegression(null); }}><option value="">Choose current audit</option>{completedAudits.map((audit) => <option value={audit.id} key={audit.id}>{audit.name} · {audit.id.slice(0, 8)}</option>)}</select></div>
        <div><label htmlFor="baseline-audit">Baseline audit</label><select id="baseline-audit" value={baselineAudit} onChange={(event) => { setBaselineAudit(event.target.value); setRegression(null); }}><option value="">Choose baseline audit</option>{completedAudits.map((audit) => <option value={audit.id} key={audit.id} disabled={audit.id === currentAudit}>{audit.name} · {audit.id.slice(0, 8)}</option>)}</select></div>
        <button className="primary-button" onClick={() => void runComparison()} disabled={busy || !selectedCurrent || !selectedBaseline || currentAudit === baselineAudit || selectedCurrent.target_id !== selectedBaseline.target_id}><GitCompareArrows size={16} /> Compare runs</button>
        {selectedCurrent && selectedBaseline && selectedCurrent.target_id !== selectedBaseline.target_id && <p className="tool-warning"><ShieldAlert size={15} /> Choose two audits for the same target.</p>}
      </div>}
      {regression && <div className="regression-results" aria-live="polite">
        <div className="regression-metrics"><div><strong>{regression.new_findings.length}</strong><span>New findings</span></div><div><strong>{regression.resolved_findings.length}</strong><span>Resolved / no longer observed</span></div><div><strong>{regression.unchanged_findings}</strong><span>Unchanged</span></div></div>
        <div className="regression-columns"><div><h3>New findings</h3>{regression.new_findings.length ? regression.new_findings.map((finding, index) => <article className="regression-item" key={`${finding.title}-${index}`}><StatusPill status={finding.severity} /><strong>{finding.title}</strong>{finding.url && <code>{finding.url}</code>}</article>) : <p className="muted-copy">No new findings in the comparison.</p>}</div><div><h3>Resolved / no longer observed</h3>{regression.resolved_findings.length ? regression.resolved_findings.map((finding, index) => <article className="regression-item" key={`${finding.title}-${index}`}><StatusPill status={finding.severity} /><strong>{finding.title}</strong>{finding.url && <code>{finding.url}</code>}</article>) : <p className="muted-copy">No findings disappeared from the current run.</p>}</div></div>
        <p className="tool-warning"><ShieldAlert size={15} /> “Resolved” means the finding was not observed in the current audit; verify manually before closing remediation.</p>
      </div>}
    </section>

    {isAdmin && <section className="panel reports-source-panel"><div className="panel__heading"><div><h2>Source workspace reports</h2><p>Reports from Trivy, Semgrep, Gitleaks and CycloneDX SBOM scans.</p></div><Download size={18} /></div>
      {completedWorkspaceRuns.length === 0 ? <EmptyState title="No completed source scans" description="Configure WEBGUARD_WORKSPACE_SCAN_ROOT and an enabled code-scanning engine to generate source reports." /> : <div className="report-source-list">{completedWorkspaceRuns.map((scan) => <article className="report-source-row" key={scan.id}><div className="report-source-row__identity"><span className="tool-run-row__icon"><FileChartColumn size={16} /></span><div><strong>{scan.engine} · source workspace</strong><small>{new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(scan.finished_at ?? scan.created_at))}</small><code>{scan.id}</code></div></div><StatusPill status={scan.state} /><div className="report-export-actions">{[...workspaceFormats, ...(scan.engine === 'sbom' ? ['cyclonedx' as const] : [])].map((format) => <button key={format} className="secondary-button" onClick={() => void exportWorkspace(scan, format)} disabled={busy}><Download size={14} /> {format.toUpperCase()}</button>)}</div></article>)}</div>}
    </section>}
  </div>;
}
