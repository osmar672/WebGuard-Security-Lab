import { getJson, postJson } from './httpClient';
import type { JobState } from './dashboardService';

export interface TargetRecord {
  id: string;
  name: string;
  base_url: string;
  hostname: string;
  scope_rules: Record<string, unknown>;
  authorization_status: 'unverified' | 'authorized' | 'revoked';
  is_lab_target: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuditRecord {
  id: string;
  target_id: string;
  name: string;
  state: JobState;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface FindingRecord {
  id: string;
  audit_id: string | null;
  workspace_scan_id?: string | null;
  scan_job_id: string | null;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'confirmed' | 'false_positive' | 'resolved';
  url: string | null;
  description: string | null;
  created_at: string;
}

export interface Paginated<T> { data: T[]; meta: { page: number; page_size: number; total: number } | null; }

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const str = (value: unknown, field: string): string => {
  if (typeof value !== 'string') throw new Error(`Invalid ${field} value from API.`);
  return value;
};
const nullableString = (value: unknown, field: string): string | null => value === null ? null : str(value, field);
const parseEnvelope = <T,>(value: unknown, parseRow: (row: unknown) => T): Paginated<T> => {
  if (!isObject(value) || !Array.isArray(value.data)) throw new Error('Expected a paginated API response.');
  const meta = isObject(value.meta) && typeof value.meta.page === 'number'
    && typeof value.meta.page_size === 'number' && typeof value.meta.total === 'number'
    ? { page: value.meta.page, page_size: value.meta.page_size, total: value.meta.total } : null;
  return { data: value.data.map(parseRow), meta };
};

function parseTarget(row: unknown): TargetRecord {
  if (!isObject(row)) throw new Error('Invalid target record.');
  const status = str(row.authorization_status, 'authorization_status');
  if (!['unverified', 'authorized', 'revoked'].includes(status)) throw new Error('Invalid authorization status.');
  if (typeof row.is_lab_target !== 'boolean' || !isObject(row.scope_rules)) throw new Error('Invalid target flags.');
  return {
    id: str(row.id, 'id'), name: str(row.name, 'name'), base_url: str(row.base_url, 'base_url'),
    hostname: str(row.hostname, 'hostname'), scope_rules: row.scope_rules,
    authorization_status: status as TargetRecord['authorization_status'], is_lab_target: row.is_lab_target,
    created_at: str(row.created_at, 'created_at'), updated_at: str(row.updated_at, 'updated_at'),
  };
}

function parseAudit(row: unknown): AuditRecord {
  if (!isObject(row)) throw new Error('Invalid audit record.');
  const state = str(row.state, 'state');
  const states: JobState[] = ['pending', 'queued', 'running', 'completed', 'failed', 'cancelled'];
  if (!states.includes(state as JobState)) throw new Error('Invalid audit state.');
  return {
    id: str(row.id, 'id'), target_id: str(row.target_id, 'target_id'), name: str(row.name, 'name'),
    state: state as JobState, created_at: str(row.created_at, 'created_at'), updated_at: str(row.updated_at, 'updated_at'),
    started_at: nullableString(row.started_at, 'started_at'), finished_at: nullableString(row.finished_at, 'finished_at'),
  };
}

function parseFinding(row: unknown): FindingRecord {
  if (!isObject(row)) throw new Error('Invalid finding record.');
  const severity = str(row.severity, 'severity');
  const status = str(row.status, 'status');
  if (!['info', 'low', 'medium', 'high', 'critical'].includes(severity)) throw new Error('Invalid finding severity.');
  if (!['open', 'confirmed', 'false_positive', 'resolved'].includes(status)) throw new Error('Invalid finding status.');
  return {
    id: str(row.id, 'id'), audit_id: nullableString(row.audit_id, 'audit_id'), workspace_scan_id: nullableString(row.workspace_scan_id, 'workspace_scan_id'), scan_job_id: nullableString(row.scan_job_id, 'scan_job_id'),
    title: str(row.title, 'title'), severity: severity as FindingRecord['severity'], status: status as FindingRecord['status'],
    url: nullableString(row.url, 'url'), description: nullableString(row.description, 'description'),
    created_at: str(row.created_at, 'created_at'),
  };
}

export async function loadTargets(): Promise<Paginated<TargetRecord>> {
  return parseEnvelope(await getJson('/api/targets?page=1&page_size=100', (value) => value), parseTarget);
}
export async function createTarget(body: { name: string; base_url: string; authorization_confirmed: true; authorization_note: string | null }): Promise<TargetRecord> {
  const value = await postJson('/api/targets', body, (payload) => {
    if (!isObject(payload) || !('data' in payload)) throw new Error('Invalid target creation response.');
    return parseTarget(payload.data);
  });
  return value;
}
export async function loadAudits(): Promise<Paginated<AuditRecord>> {
  return parseEnvelope(await getJson('/api/audits?page=1&page_size=100', (value) => value), parseAudit);
}
export async function loadFindings(): Promise<Paginated<FindingRecord>> {
  return parseEnvelope(await getJson('/api/findings?page=1&page_size=100', (value) => value), parseFinding);
}
