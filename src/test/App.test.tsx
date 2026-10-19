import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../App';

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

describe('WebGuard Phase 1 frontend', () => {
  it('renders the dashboard without fabricating backend metrics', async () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    expect(screen.getByText('Backend contract needs configuration')).toBeInTheDocument();
    expect(await screen.findAllByText('Not configured')).not.toHaveLength(0);
    expect(screen.getAllByText(/API endpoint not configured/i).length).toBeGreaterThan(0);
  });

  it('supports sidebar navigation to Targets', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('link', { name: 'Targets' }));
    expect(screen.getByRole('heading', { name: 'Authorized targets' })).toBeInTheDocument();
    expect(screen.getByText('Backend contract required')).toBeInTheDocument();
  });

  it('shows scanner as coming soon and does not imply a scan runs', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('link', { name: 'Security Scanner' }));
    expect(screen.getByText('Coming soon')).toBeInTheDocument();
    expect(screen.getByText(/does not run scans, browser actions, or load generation/i)).toBeInTheDocument();
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

  it('lists endpoint placeholders in Settings', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('link', { name: 'Settings' }));
    expect(screen.getByRole('heading', { name: 'Endpoint configuration' })).toBeInTheDocument();
    expect(screen.getByText('VITE_API_HEALTH_PATH')).toBeInTheDocument();
    expect(screen.getByText(/Never put API keys, passwords, tokens/i)).toBeInTheDocument();
  });
});
