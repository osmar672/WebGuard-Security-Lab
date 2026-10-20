import { apiBaseUrl } from './config';
import { getAccessToken } from './session';
import { getJson, postJson } from './httpClient';

export type ToolState = 'available' | 'disabled' | 'not_configured' | 'not_implemented' | 'unavailable';
export type ToolProfile = 'quick' | 'standard' | 'exhaustive';
export type ToolCategory = 'web_security' | 'api_testing' | 'browser' | 'performance' | 'code_security' | 'configuration';
export type RunState = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ToolCatalogItem {
  id: string;
  name: string;
  category: ToolCategory;
  description: string;
  kind: 'builtin' | 'external';
  state: ToolState;
  detail: string;
  profiles: ToolProfile[];
  requires_target: boolean;
  active_testing: boolean;
}
export interface ToolFinding {
  id?: string;
  title: string;
  severity: string;
  url?: string | null;
  description?: string;
  evidence?: Record<string, unknown>;
}
export interface ToolRun {
  id: string;
  audit_id: string;
  target_id: string;
  target_name: string;
  engine: string;
  state: RunState;
  progress: number;
  profile: string;
  results: { summary?: Record<string, unknown>; findings?: ToolFinding[]; notes?: string[]; finding_count?: number; [key: string]: unknown };
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}
export interface WorkspaceRun {
  id: string;
  engine: string;
  profile: string;
  state: RunState;
  progress: number;
  results: ToolRun['results'];
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}
export interface ApiPage<T> {
  data: T[];
  meta: { page: number; page_size: number; total: number } | null;
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const string = (value: unknown, field: string): string => {
  if (typeof value !== 'string') throw new Error(`Invalid ${field} returned by API.`);
  return value;
};
const nullableString = (value: unknown, field: string): string | null => value === null ? null : string(value, field);
const number = (value: unknown, field: string): number => {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`Invalid ${field} returned by API.`);
  return value;
};
const object = (value: unknown, field: string): Record<string, unknown> => {
  if (!isObject(value)) throw new Error(`Invalid ${field} returned by API.`);
  return value;
};
const unwrap = (value: unknown): unknown => {
  const response = object(value, 'response');
  if (!('data' in response)) throw new Error('Response envelope is missing data.');
  return response.data;
};
const parsePage = <T,>(value: unknown, parseRow: (row: unknown) => T): ApiPage<T> => {
  const response = object(value, 'page response');
  if (!Array.isArray(response.data)) throw new Error('Expected a list response.');
  const metaValue = response.meta;
  const meta = isObject(metaValue) ? {
    page: number(metaValue.page, 'meta.page'), page_size: number(metaValue.page_size, 'meta.page_size'), total: number(metaValue.total, 'meta.total'),
  } : null;
  return { data: response.data.map(parseRow), meta };
};
const validStates: RunState[] = ['pending', 'queued', 'running', 'completed', 'failed', 'cancelled'];
function parseTool(row: unknown): ToolCatalogItem {
  const x = object(row, 'tool catalog item');
  const state = string(x.state, 'tool state') as ToolState;
  const category = string(x.category, 'tool category') as ToolCategory;
  if (!['available', 'disabled', 'not_configured', 'not_implemented', 'unavailable'].includes(state)) throw new Error('Unsupported tool state.');
  if (!['web_security', 'api_testing', 'browser', 'performance', 'code_security', 'configuration'].includes(category)) throw new Error('Unsupported tool category.');
  if (!Array.isArray(x.profiles) || typeof x.requires_target !== 'boolean' || typeof x.active_testing !== 'boolean') throw new Error('Invalid tool flags.');
  return { id: string(x.id, 'tool.id'), name: string(x.name, 'tool.name'), category, description: string(x.description, 'tool.description'),
    kind: string(x.kind, 'tool.kind') as ToolCatalogItem['kind'], state, detail: string(x.detail, 'tool.detail'),
    profiles: x.profiles as ToolProfile[], requires_target: x.requires_target, active_testing: x.active_testing };
}
function parseResults(value: unknown): ToolRun['results'] {
  if (!isObject(value)) return {};
  const result: ToolRun['results'] = { ...value };
  if (Array.isArray(value.findings)) {
    result.findings = value.findings.filter(isObject).map((item) => ({
      title: typeof item.title === 'string' ? item.title : 'Untitled finding',
      severity: typeof item.severity === 'string' ? item.severity : 'info',
      url: typeof item.url === 'string' ? item.url : null,
      description: typeof item.description === 'string' ? item.description : '',
      evidence: isObject(item.evidence) ? item.evidence : {},
    }));
  }
  if (isObject(value.summary)) result.summary = value.summary;
  if (Array.isArray(value.notes)) result.notes = value.notes.filter((item): item is string => typeof item === 'string');
  if (typeof value.finding_count === 'number') result.finding_count = value.finding_count;
  return result;
}
function parseRun(row: unknown): ToolRun {
  const x = object(row, 'tool run');
  const state = string(x.state, 'run.state') as RunState;
  if (!validStates.includes(state)) throw new Error('Unsupported run state.');
  return { id: string(x.id, 'run.id'), audit_id: string(x.audit_id, 'run.audit_id'), target_id: string(x.target_id, 'run.target_id'),
    target_name: string(x.target_name, 'run.target_name'), engine: string(x.engine, 'run.engine'), state,
    progress: number(x.progress, 'run.progress'), profile: string(x.profile, 'run.profile'), results: parseResults(x.results),
    error_message: nullableString(x.error_message, 'run.error_message'), started_at: nullableString(x.started_at, 'run.started_at'),
    finished_at: nullableString(x.finished_at, 'run.finished_at'), created_at: string(x.created_at, 'run.created_at') };
}
function parseWorkspaceRun(row: unknown): WorkspaceRun {
  const x = object(row, 'workspace run');
  const state = string(x.state, 'workspace state') as RunState;
  if (!validStates.includes(state)) throw new Error('Unsupported workspace state.');
  return { id: string(x.id, 'workspace.id'), engine: string(x.engine, 'workspace.engine'), profile: string(x.profile, 'workspace.profile'),
    state, progress: number(x.progress, 'workspace.progress'), results: parseResults(x.results),
    error_message: nullableString(x.error_message, 'workspace.error_message'), started_at: nullableString(x.started_at, 'workspace.started_at'),
    finished_at: nullableString(x.finished_at, 'workspace.finished_at'), created_at: string(x.created_at, 'workspace.created_at') };
}

export async function loadToolCatalog(): Promise<ToolCatalogItem[]> {
  return (unwrap(await getJson('/api/tools/catalog', (value) => value)) as unknown[]).map(parseTool);
}
export async function loadToolRuns(): Promise<ToolRun[]> {
  return parsePage(await getJson('/api/tools/runs?page=1&page_size=50', (value) => value), parseRun).data;
}
export async function createToolRun(input: { engine: string; target_id: string; profile: ToolProfile; authorization_confirmed: true }): Promise<ToolRun> {
  return parseRun(unwrap(await postJson('/api/tools/runs', input, (value) => value)));
}
export async function cancelToolRun(id: string): Promise<ToolRun> {
  return parseRun(unwrap(await postJson(`/api/tools/runs/${encodeURIComponent(id)}/cancel`, {}, (value) => value)));
}
export async function loadWorkspaceRuns(): Promise<WorkspaceRun[]> {
  return parsePage(await getJson('/api/tools/workspace-runs?page=1&page_size=50', (value) => value), parseWorkspaceRun).data;
}
export async function createWorkspaceRun(input: { engine: 'trivy' | 'semgrep' | 'gitleaks' | 'sbom'; profile: ToolProfile; authorization_confirmed: true }): Promise<WorkspaceRun> {
  return parseWorkspaceRun(unwrap(await postJson('/api/tools/workspace-runs', input, (value) => value)));
}
export async function cancelWorkspaceRun(id: string): Promise<WorkspaceRun> {
  return parseWorkspaceRun(unwrap(await postJson(`/api/tools/workspace-runs/${encodeURIComponent(id)}/cancel`, {}, (value) => value)));
}
export async function authorizeTarget(id: string, note: string) {
  return unwrap(await postJson(`/api/targets/${encodeURIComponent(id)}/authorize`, { confirmed: true, note }, (value) => value));
}
export async function revokeTarget(id: string) {
  return unwrap(await postJson(`/api/targets/${encodeURIComponent(id)}/revoke`, {}, (value) => value));
}

export async function downloadReport(options: { auditId?: string; workspaceScanId?: string; format: 'json' | 'html' | 'pdf' | 'sarif' | 'cyclonedx' }): Promise<void> {
  const params = new URLSearchParams({ format: options.format });
  if (options.auditId) params.set('audit_id', options.auditId);
  if (options.workspaceScanId) params.set('workspace_scan_id', options.workspaceScanId);
  const base = apiBaseUrl ? apiBaseUrl.replace(/\/$/, '') : window.location.origin;
  const url = new URL(`/api/reports/export?${params.toString()}`, base);
  if (url.origin !== new URL(base).origin) throw new Error('Report URL must remain on the API origin.');
  const token = getAccessToken();
  const response = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {}, credentials: 'omit', cache: 'no-store', redirect: 'error' });
  if (!response.ok) throw new Error(`Report export failed with HTTP ${response.status}.`);
  const blob = await response.blob();
  const link = document.createElement('a');
  const disposition = response.headers.get('content-disposition') ?? '';
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  link.download = match?.[1] ?? `webguard-report.${options.format}`;
  const objectUrl = URL.createObjectURL(blob);
  link.href = objectUrl;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}

export interface RegressionReport {
  baseline_audit_id: string;
  current_audit_id: string;
  new_findings: Array<{ title: string; severity: string; url: string | null; status: string }>;
  resolved_findings: Array<{ title: string; severity: string; url: string | null; status: string }>;
  unchanged_findings: number;
}
export async function compareAudits(currentId: string, baselineId: string): Promise<RegressionReport> {
  const value = unwrap(await getJson(`/api/audits/${encodeURIComponent(currentId)}/regression?baseline_audit_id=${encodeURIComponent(baselineId)}`, (data) => data));
  const x = object(value, 'regression report');
  return { baseline_audit_id: string(x.baseline_audit_id, 'baseline_audit_id'), current_audit_id: string(x.current_audit_id, 'current_audit_id'),
    new_findings: Array.isArray(x.new_findings) ? x.new_findings.filter(isObject).map((f) => ({ title: String(f.title ?? ''), severity: String(f.severity ?? 'info'), url: typeof f.url === 'string' ? f.url : null, status: String(f.status ?? 'open') })) : [],
    resolved_findings: Array.isArray(x.resolved_findings) ? x.resolved_findings.filter(isObject).map((f) => ({ title: String(f.title ?? ''), severity: String(f.severity ?? 'info'), url: typeof f.url === 'string' ? f.url : null, status: String(f.status ?? 'open') })) : [],
    unchanged_findings: number(x.unchanged_findings, 'unchanged_findings') };
}

export interface HistoryEvent {
  id: string;
  entity_type: string;
  entity_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: string;
}
export async function loadHistoryEvents(): Promise<{ data: HistoryEvent[]; total: number | null }> {
  const response = object(await getJson('/api/history?page=1&page_size=100', (value) => value), 'history response');
  if (!Array.isArray(response.data)) throw new Error('Invalid audit history response.');
  const data: HistoryEvent[] = response.data.map((value) => {
    const x = object(value, 'history event');
    return { id: string(x.id, 'history.id'), entity_type: string(x.entity_type, 'history.entity_type'),
      entity_id: string(x.entity_id, 'history.entity_id'), event_type: string(x.event_type, 'history.event_type'),
      payload: isObject(x.payload) ? x.payload : {}, created_at: string(x.created_at, 'history.created_at') };
  });
  const meta = isObject(response.meta) && typeof response.meta.total === 'number' ? response.meta.total : null;
  return { data, total: meta };
}
