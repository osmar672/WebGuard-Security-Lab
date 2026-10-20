/**
 * Paths are taken from docs/API_CONTRACT.md and exist in the supplied FastAPI app.
 * Future engines/routes stay empty until their backend implementation exists.
 */
export interface ApiPaths {
  health: string;
  dashboardSummary: string;
  engines: string;
  targets: string;
  audits: string;
  findings: string;
  aiStatus: string;
  aiAssist: string;
  toolsCatalog: string;
  toolRuns: string;
  workspaceRuns: string;
  history: string;
  reportExport: string;
  scannerJobs: string;
  browserBots: string;
  loadTests: string;
  reports: string;
  auditHistory: string;
  recentActivity: string;
}

// Empty base URL means same-origin: Vite proxies /api in development and Caddy does it in production.
export const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? '').trim();

export const apiPaths: ApiPaths = {
  health: '/api/health',
  dashboardSummary: '/api/dashboard/summary',
  engines: '/api/engines/status',
  targets: '/api/targets',
  audits: '/api/audits',
  findings: '/api/findings',
  aiStatus: '/api/ai/status',
  aiAssist: '/api/ai/assist',
  toolsCatalog: '/api/tools/catalog',
  toolRuns: '/api/tools/runs',
  workspaceRuns: '/api/tools/workspace-runs',
  history: '/api/history',
  reportExport: '/api/reports/export',
  scannerJobs: '/api/tools/runs',
  browserBots: '/api/tools/runs',
  loadTests: '/api/tools/runs',
  reports: '/api/reports/export',
  auditHistory: '/api/history',
  recentActivity: '/api/history',
};

export const isValidApiBaseUrl = (rawUrl: string): boolean => {
  if (!rawUrl.trim()) return true;
  try {
    const url = new URL(rawUrl);
    return (url.protocol === 'http:' || url.protocol === 'https:')
      && !url.username && !url.password && !url.search && !url.hash;
  } catch {
    return false;
  }
};
