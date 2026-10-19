/**
 * The provided Phase 0 file states that API paths/schemas must be defined, but it
 * does not contain an approved API_CONTRACT.md. Paths are therefore explicit
 * placeholders and intentionally default to empty rather than guessed routes.
 */
export interface ApiPaths {
  health: string;
  databaseHealth: string;
  targetsCount: string;
  auditsCount: string;
  recentJobs: string;
  engineStatus: string;
  recentActivity: string;
  targets: string;
  scannerJobs: string;
  browserBots: string;
  loadTests: string;
  findings: string;
  reports: string;
  auditHistory: string;
}

const readPath = (value: string | undefined): string => value?.trim() ?? '';

export const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? '').trim();

export const apiPaths: ApiPaths = {
  health: readPath(import.meta.env.VITE_API_HEALTH_PATH),
  databaseHealth: readPath(import.meta.env.VITE_API_DATABASE_HEALTH_PATH),
  targetsCount: readPath(import.meta.env.VITE_API_TARGETS_COUNT_PATH),
  auditsCount: readPath(import.meta.env.VITE_API_AUDITS_COUNT_PATH),
  recentJobs: readPath(import.meta.env.VITE_API_RECENT_JOBS_PATH),
  engineStatus: readPath(import.meta.env.VITE_API_ENGINE_STATUS_PATH),
  recentActivity: readPath(import.meta.env.VITE_API_RECENT_ACTIVITY_PATH),
  targets: readPath(import.meta.env.VITE_API_TARGETS_PATH),
  scannerJobs: readPath(import.meta.env.VITE_API_SCANNER_JOBS_PATH),
  browserBots: readPath(import.meta.env.VITE_API_BROWSER_BOTS_PATH),
  loadTests: readPath(import.meta.env.VITE_API_LOAD_TESTS_PATH),
  findings: readPath(import.meta.env.VITE_API_FINDINGS_PATH),
  reports: readPath(import.meta.env.VITE_API_REPORTS_PATH),
  auditHistory: readPath(import.meta.env.VITE_API_AUDIT_HISTORY_PATH),
};

export const isValidApiBaseUrl = (rawUrl: string): boolean => {
  try {
    const url = new URL(rawUrl);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
};
