export interface SessionUser {
  id: string;
  email: string;
  role: 'admin' | 'operator' | 'viewer';
  is_active: boolean;
  created_at: string;
}

const TOKEN_KEY = 'webguard_access_token';
const USER_KEY = 'webguard_session_user';

export function getAccessToken(): string | null {
  try { return window.sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

export function setAccessToken(token: string): void {
  try { window.sessionStorage.setItem(TOKEN_KEY, token); } catch {
    throw new Error('Browser session storage is unavailable. Enable session storage to sign in safely.');
  }
}

export function setSessionUser(user: SessionUser): void {
  try { window.sessionStorage.setItem(USER_KEY, JSON.stringify(user)); } catch { /* token remains session-scoped */ }
}

export function getSessionUser(): SessionUser | null {
  try {
    const raw = window.sessionStorage.getItem(USER_KEY);
    if (!raw) return null;
    const value: unknown = JSON.parse(raw);
    if (typeof value !== 'object' || value === null || !('email' in value) || !('role' in value)) return null;
    return value as SessionUser;
  } catch { return null; }
}

export function clearAccessToken(): void {
  try {
    window.sessionStorage.removeItem(TOKEN_KEY);
    window.sessionStorage.removeItem(USER_KEY);
  } catch { /* no-op when browser storage is disabled */ }
}
