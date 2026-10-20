import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../App';

const auditStates = { pending: 0, queued: 0, running: 0, completed: 0, failed: 0, cancelled: 0 };

function stubBackend() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    let body: unknown;
    if (url.endsWith('/api/auth/login')) {
      body = { access_token: 'test-access-token', token_type: 'bearer', expires_in: 900, user: { id: 'test-user', email: 'admin@example.com', role: 'admin', is_active: true, created_at: '2026-10-19T12:00:00Z' } };
    } else if (url.endsWith('/api/health')) {
      body = { status: 'ok', api: 'ok', database: 'ok', version: '0.2.0', time: '2026-10-19T12:00:00Z' };
    } else if (url.endsWith('/api/ai/status')) {
      body = { data: { configured: false, mode: 'local_rules', provider: 'Local rule-based assistant', model: null, capabilities: ['process_review', 'audit_summary', 'finding_triage', 'remediation_plan', 'general_guidance'], privacy_note: 'No external model is configured; analysis remains local and uses deterministic rules.' } };
    } else if (url.endsWith('/api/ai/assist')) {
      body = { data: { task: 'process_review', answer: '## Revisión operativa\nObjetivos registrados: **0**.', mode: 'local_rules', provider: 'Local rule-based assistant', model: null, generated_at: '2026-10-19T12:00:00Z', disclaimer: 'AI output is advisory.' } };
    } else if (url.endsWith('/api/dashboard/summary')) {
      body = { data: { targets: 0, audits_by_state: auditStates, findings_by_severity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, open_findings: 0, recent_audits: [] } };
    } else if (url.endsWith('/api/engines/status')) {
      body = { data: [{ name: 'zap', kind: 'scanner', state: 'not_configured', detail: 'set WEBGUARD_ZAP_API_URL' }] };
    } else {
      body = { data: [], meta: { page: 1, page_size: 20, total: 0 } };
    }
    return { ok: true, status: 200, json: async () => body } as Response;
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  window.sessionStorage.clear();
  vi.unstubAllGlobals();
});

beforeEach(() => {
  stubBackend();
  window.sessionStorage.setItem('webguard_access_token', 'test-access-token');
});

describe('WebGuard Security Lab frontend', () => {
  it('redirects unauthenticated users to the login screen and signs in', async () => {
    window.sessionStorage.clear();
    const user = userEvent.setup();
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Sign in to your workspace' })).toBeInTheDocument();
    await user.type(screen.getByLabelText('Email address'), 'admin@example.com');
    await user.type(screen.getByLabelText('Password'), 'a-safe-test-password');
    await user.click(screen.getByRole('button', { name: /Sign in/i }));
    expect(await screen.findByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    expect(window.sessionStorage.getItem('webguard_access_token')).toBe('test-access-token');
  });

  it('renders truthful live backend values and empty states', async () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    expect(await screen.findByText('Backend connected')).toBeInTheDocument();
    expect(await screen.findByText('No audits yet')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Recent activity' })).toBeInTheDocument();
    expect(screen.getByText('9 / 14')).toBeInTheDocument();
  });

  it('supports sidebar navigation to Targets', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('link', { name: 'Targets' }));
    expect(screen.getByRole('heading', { name: 'Registered targets' })).toBeInTheDocument();
    expect(await screen.findByText('No targets registered')).toBeInTheDocument();
  });

  it('shows scanner as coming soon and does not imply a scan runs', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('link', { name: /Security Scanner/ }));
    expect(screen.getByText('Coming soon')).toBeInTheDocument();
    expect(screen.getByText(/does not run scans, browser actions, or load generation/i)).toBeInTheDocument();
  });

  it('opens AI Copilot and runs a local process review', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('link', { name: 'AI Copilot' }));
    expect(await screen.findByRole('heading', { name: 'AI Copilot', level: 1 })).toBeInTheDocument();
    expect(await screen.findByText('Asistente local activo')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Generar recomendaciones/i }));
    expect(await screen.findByText(/Objetivos registrados: \*\*0\*\*/)).toBeInTheDocument();
  });

  it('toggles between dark and light themes accessibly', async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    expect(container.querySelector('.app-shell')).toHaveClass('theme-dark');
    await user.click(screen.getByRole('button', { name: 'Switch to light theme' }));
    expect(container.querySelector('.app-shell')).toHaveClass('theme-light');
    await user.click(screen.getByRole('button', { name: 'Switch to dark theme' }));
    expect(container.querySelector('.app-shell')).toHaveClass('theme-dark');
  });

  it('lists official and future API endpoints in Settings', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('link', { name: 'Settings' }));
    expect(screen.getByRole('heading', { name: 'Endpoint configuration' })).toBeInTheDocument();
    expect(screen.getByText('/api/health')).toBeInTheDocument();
    expect(screen.getByText(/Never put API keys, passwords, tokens/i)).toBeInTheDocument();
  });
});
