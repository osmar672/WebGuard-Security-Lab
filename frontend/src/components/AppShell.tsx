import { useState } from 'react';
import { Menu, Moon, Sun, ChevronRight, Radio, LogOut } from 'lucide-react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { clearAccessToken, getSessionUser } from '../api/session';
import { Sidebar } from './Sidebar';
import { pageCopy } from './navigation';

export function AppShell() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      return window.localStorage.getItem('webguard-theme') === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const copy = pageCopy[location.pathname] ?? pageCopy['/'];
  const sessionUser = getSessionUser();

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    try { window.localStorage.setItem('webguard-theme', nextTheme); } catch { /* storage may be disabled */ }
  };

  return (
    <div className={`app-shell theme-${theme}`}>
      <Sidebar mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} />
      <div className="app-main">
        <header className="topbar">
          <button className="icon-button topbar__menu" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={20} /></button>
          <div className="breadcrumb"><span>{copy.eyebrow.split(' / ')[0]}</span><ChevronRight size={14} aria-hidden="true" /><strong>{copy.eyebrow.split(' / ').slice(1).join(' / ')}</strong></div>
          <div className="topbar__actions">
            <span className="connection-label"><Radio size={14} aria-hidden="true" /><span>Authenticated</span></span>
            <span className="topbar__separator" />
            <button className="icon-button theme-toggle" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
              {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <span className="session-user-label">{sessionUser?.email ?? 'Signed in'}</span><button className="signout-button" onClick={() => { clearAccessToken(); navigate('/login', { replace: true }); }}><LogOut size={15} aria-hidden="true" /> <span>Sign out</span></button>
          </div>
        </header>
        <main className="page-content">
          <div className="page-heading">
            <div><p className="eyebrow">{copy.eyebrow}</p><h1>{copy.title}</h1><p className="page-heading__description">{copy.description}</p></div>
            <div className="page-heading__meta"><span className="live-dot" />Frontend ready</div>
          </div>
          <Outlet />
          <footer className="page-footer"><span>WebGuard Security Lab</span><span>Phase 1 · Frontend module</span><span>Authorized systems only</span></footer>
        </main>
      </div>
    </div>
  );
}
