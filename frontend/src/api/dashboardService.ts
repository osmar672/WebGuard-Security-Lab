import { apiPaths } from './config';
import { getJson } from './httpClient';

export type JobState = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type Resource<T> =
  | { kind: 'loading' }
  | { kind: 'not-configured'; message: string }
  | { kind: 'error'; message: string }
  | { kind: 'loaded'; data: T };

export interface HealthSummary {
  status: string;
  checked_at?: string;
  message?: string;
}

export interface RecentJob {
  id: string;
  name: string;
  status: JobState;
  created_at: string;
}

export interface EngineStatus {
  name: string;
  status: string;
  message?: string;
}

export interface ActivityEvent {
  id: string;
  action: string;
  created_at: string;
  actor?: string;
}

export interface DashboardSnapshot {
  backendHealth: Resource<HealthSummary>;
  databaseHealth: Resource<HealthSummary>;
  targetCount: Resource<number>;
  auditCount: Resource<number>;
  recentJobs: Resource<RecentJob[]>;
  engineStatuses: Resource<EngineStatus[]>;
  recentActivity: Resource<ActivityEvent[]>;
}

interface HealthPayload {
  status: string;
  database: string;
  time: string;
}

interface SummaryPayload {
  targets: number;
  audits_by_state: Record<string, number>;
  recent_audits: RecentJob[];
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const requireString = (value: unknown, field: string): string => {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`"${field}" must be a non-empty string`);
  return value;
};

const requireCount = (value: unknown, field: string): number => {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`"${field}" must be a non-negative integer`);
  }
  return value;
};

const unwrapData = (input: unknown): unknown => {
  if (!isObject(input) || !('data' in input)) throw new Error('expected API response envelope { data: ... }');
  return input.data;
};

const decodeHealth = (input: unknown): HealthPayload => {
  if (!isObject(input)) throw new Error('expected health response object');
  const status = requireString(input.status, 'status');
  const database = requireString(input.database, 'database');
  const time = requireString(input.time, 'time');
  if (!['ok', 'degraded'].includes(status)) throw new Error(`unsupported health status "${status}"`);
  if (!['ok', 'unavailable'].includes(database)) throw new Error(`unsupported database status "${database}"`);
  return { status, database, time };
};

const decodeSummary = (input: unknown): SummaryPayload => {
  const data = unwrapData(input);
  if (!isObject(data)) throw new Error('dashboard summary data must be an object');
  const targets = requireCount(data.targets, 'targets');
  if (!isObject(data.audits_by_state)) throw new Error('audits_by_state must be an object');
  const auditsByState: Record<string, number> = {};
  for (const [state, count] of Object.entries(data.audits_by_state)) {
    auditsByState[state] = requireCount(count, `audits_by_state.${state}`);
  }
  if (!Array.isArray(data.recent_audits)) throw new Error('recent_audits must be an array');
  const allowedStates: JobState[] = ['pending', 'queued', 'running', 'completed', 'failed', 'cancelled'];
  const recentAudits: RecentJob[] = data.recent_audits.map((item: unknown) => {
    if (!isObject(item)) throw new Error('recent audit must be an object');
    const status = requireString(item.state, 'state') as JobState;
    if (!allowedStates.includes(status)) throw new Error(`unsupported audit state "${status}"`);
    return {
      id: requireString(item.id, 'id'),
      name: requireString(item.name, 'name'),
      status,
      created_at: requireString(item.created_at, 'created_at'),
    };
  });
  return { targets, audits_by_state: auditsByState, recent_audits: recentAudits };
};

const decodeEngines = (input: unknown): EngineStatus[] => {
  const data = unwrapData(input);
  if (!Array.isArray(data)) throw new Error('engine status data must be an array');
  return data.map((item: unknown) => {
    if (!isObject(item)) throw new Error('engine status item must be an object');
    return {
      name: requireString(item.name, 'name'),
      status: requireString(item.state, 'state'),
      message: requireString(item.detail, 'detail'),
    };
  });
};

async function loadResource<T>(path: string, decoder: (input: unknown) => T): Promise<Resource<T>> {
  if (!path) {
    return { kind: 'not-configured', message: 'This endpoint is reserved for a later phase and is not implemented by the current backend.' };
  }
  try {
    return { kind: 'loaded', data: await getJson(path, decoder) };
  } catch (error) {
    return { kind: 'error', message: error instanceof Error ? error.message : 'Unknown API error.' };
  }
}

function mapResource<T, U>(resource: Resource<T>, transform: (value: T) => U): Resource<U> {
  if (resource.kind === 'loaded') return { kind: 'loaded', data: transform(resource.data) };
  return resource;
}

export async function loadDashboardSnapshot(): Promise<DashboardSnapshot> {
  const [health, summary, engineStatuses] = await Promise.all([
    loadResource(apiPaths.health, decodeHealth),
    loadResource(apiPaths.dashboardSummary, decodeSummary),
    loadResource(apiPaths.engines, decodeEngines),
  ]);

  return {
    backendHealth: mapResource(health, (value) => ({ status: value.status, checked_at: value.time })),
    databaseHealth: mapResource(health, (value) => ({
      status: value.database,
      checked_at: value.time,
      message: value.database === 'ok' ? 'Database connection verified' : 'Database connection unavailable',
    })),
    targetCount: mapResource(summary, (value) => value.targets),
    auditCount: mapResource(summary, (value) => Object.values(value.audits_by_state).reduce((sum, count) => sum + count, 0)),
    recentJobs: mapResource(summary, (value) => value.recent_audits),
    engineStatuses,
    recentActivity: { kind: 'not-configured', message: 'The current backend contract does not expose a recent-activity events endpoint yet.' },
  };
}
