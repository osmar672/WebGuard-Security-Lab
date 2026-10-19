import { apiPaths } from './config';
import { getJson } from './httpClient';

/**
 * PLACEHOLDER DISPLAY MODELS, not Phase 0-approved backend schemas.
 * Replace the decoders below after the backend owner supplies API_CONTRACT.md.
 */
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

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const requireString = (value: unknown, field: string): string => {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`"${field}" must be a non-empty string`);
  return value;
};

const decodeHealth = (input: unknown): HealthSummary => {
  if (!isObject(input)) throw new Error('expected an object');
  const checkedAt = input.checked_at;
  const message = input.message;
  return {
    status: requireString(input.status, 'status'),
    ...(typeof checkedAt === 'string' ? { checked_at: checkedAt } : {}),
    ...(typeof message === 'string' ? { message } : {}),
  };
};

const decodeCount = (input: unknown): number => {
  if (!isObject(input) || !Number.isSafeInteger(input.count) || Number(input.count) < 0) {
    throw new Error('expected { count: non-negative integer }');
  }
  return Number(input.count);
};

const allowedStates: JobState[] = ['pending', 'queued', 'running', 'completed', 'failed', 'cancelled'];
const decodeJobs = (input: unknown): RecentJob[] => {
  if (!isObject(input) || !Array.isArray(input.items)) throw new Error('expected { items: [...] }');
  return input.items.map((item: unknown) => {
    if (!isObject(item)) throw new Error('job must be an object');
    const status = requireString(item.status, 'status') as JobState;
    if (!allowedStates.includes(status)) throw new Error(`unsupported job state "${status}"`);
    return {
      id: requireString(item.id, 'id'),
      name: requireString(item.name, 'name'),
      status,
      created_at: requireString(item.created_at, 'created_at'),
    };
  });
};

const decodeEngines = (input: unknown): EngineStatus[] => {
  if (!isObject(input) || !Array.isArray(input.items)) throw new Error('expected { items: [...] }');
  return input.items.map((item: unknown) => {
    if (!isObject(item)) throw new Error('engine must be an object');
    return {
      name: requireString(item.name, 'name'),
      status: requireString(item.status, 'status'),
      ...(typeof item.message === 'string' ? { message: item.message } : {}),
    };
  });
};

const decodeActivity = (input: unknown): ActivityEvent[] => {
  if (!isObject(input) || !Array.isArray(input.items)) throw new Error('expected { items: [...] }');
  return input.items.map((item: unknown) => {
    if (!isObject(item)) throw new Error('activity item must be an object');
    return {
      id: requireString(item.id, 'id'),
      action: requireString(item.action, 'action'),
      created_at: requireString(item.created_at, 'created_at'),
      ...(typeof item.actor === 'string' ? { actor: item.actor } : {}),
    };
  });
};

async function loadResource<T>(path: string, decoder: (input: unknown) => T): Promise<Resource<T>> {
  if (!path) {
    return {
      kind: 'not-configured',
      message: 'API endpoint not configured. The supplied Phase 0 file does not include the approved endpoint path or response schema.',
    };
  }
  try {
    return { kind: 'loaded', data: await getJson(path, decoder) };
  } catch (error) {
    return { kind: 'error', message: error instanceof Error ? error.message : 'Unknown API error.' };
  }
}

export async function loadDashboardSnapshot(): Promise<DashboardSnapshot> {
  const [backendHealth, databaseHealth, targetCount, auditCount, recentJobs, engineStatuses, recentActivity] = await Promise.all([
    loadResource(apiPaths.health, decodeHealth),
    loadResource(apiPaths.databaseHealth, decodeHealth),
    loadResource(apiPaths.targetsCount, decodeCount),
    loadResource(apiPaths.auditsCount, decodeCount),
    loadResource(apiPaths.recentJobs, decodeJobs),
    loadResource(apiPaths.engineStatus, decodeEngines),
    loadResource(apiPaths.recentActivity, decodeActivity),
  ]);
  return { backendHealth, databaseHealth, targetCount, auditCount, recentJobs, engineStatuses, recentActivity };
}
