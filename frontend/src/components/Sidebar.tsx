import { X, ShieldCheck } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import { groupLabels, navigationItems, type NavigationItem } from './navigation';

const groups: NavigationItem['group'][] = ['workspace', 'operations', 'insights', 'system'];

export function Sidebar({ mobileOpen, onClose }: { mobileOpen: boolean; onClose: () => void }) {
  return (
    <>
      {mobileOpen && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={onClose} />}
      <aside className={`sidebar${mobileOpen ? ' sidebar--open' : ''}`} aria-label="Main navigation">
        <div className="sidebar__brand-row">
          <div className="brand-mark"><ShieldCheck size={24} aria-hidden="true" /></div>
          <div className="brand-copy"><strong>WEBGUARD</strong><span>SECURITY LAB</span></div>
          <button className="icon-button sidebar__close" aria-label="Close navigation" onClick={onClose}><X size={18} /></button>
        </div>
        <div className="workspace-switcher">
          <div className="workspace-switcher__dot" />
          <div className="workspace-switcher__copy"><span>Workspace</span><strong>Security Lab</strong></div>
          <span className="workspace-switcher__chevron">⌄</span>
        </div>
        <nav className="sidebar__nav">
          {groups.map((group) => {
            const items = navigationItems.filter((item) => item.group === group);
            return (
              <div className="nav-group" key={group}>
                <div className="nav-group__label">{groupLabels[group]}</div>
                {items.map(({ label, path, icon: Icon }) => (
                  <NavLink
                    key={path}
                    to={path}
                    end={path === '/'}
                    onClick={onClose}
                    className={({ isActive }) => `nav-link${isActive ? ' nav-link--active' : ''}`}
                  >
                    <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
                    <span>{label}</span>
                    {path === '/scanner' && <span className="nav-link__dot" aria-label="module not configured" />}
                  </NavLink>
                ))}
              </div>
            );
          })}
        </nav>
        <div className="sidebar__footer">
          <div className="scope-note__icon"><ShieldCheck size={16} aria-hidden="true" /></div>
          <div><strong>Authorized testing only</strong><p>All jobs require a server-side scope grant.</p></div>
        </div>
        <div className="sidebar__version"><span>WebGuard Security Lab</span><span>Frontend · Phase 1</span></div>
      </aside>
    </>
  );
}
