import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useCurrentSession, useSession } from '../auth/SessionContext.js';
import { NoticeRegion } from './Announcer.js';

interface NavItem {
  to: string;
  label: string;
  /** No backend yet: the route explains what will live there. */
  planned?: true;
}

/** Order follows spec §10.1. */
export const NAV_ITEMS: readonly NavItem[] = [
  { to: '/', label: 'Overview' },
  { to: '/applications', label: 'Applications' },
  { to: '/connections', label: 'Connections' },
  { to: '/vault', label: 'Vault', planned: true },
  { to: '/agents', label: 'Agents' },
  { to: '/policies', label: 'Policies', planned: true },
  { to: '/workflows', label: 'Workflows', planned: true },
  { to: '/approvals', label: 'Approvals', planned: true },
  { to: '/activity', label: 'Activity & Audit' },
  { to: '/settings', label: 'Settings', planned: true },
];

export function Shell() {
  const session = useCurrentSession();
  const { signOut } = useSession();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);

  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>

      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">Agent Access Broker</span>
        </div>
        <button
          type="button"
          className="button menu-toggle"
          aria-expanded={menuOpen}
          aria-controls="primary-nav"
          onClick={() => setMenuOpen((open) => !open)}
        >
          Menu
        </button>
        <div className="account">
          <span className="account-org">{session.organization.name}</span>
          <span className="account-user">{session.user.email}</span>
          <button
            type="button"
            className="button"
            disabled={signingOut}
            onClick={() => {
              setSigningOut(true);
              void signOut();
            }}
          >
            Sign out
          </button>
        </div>
      </header>

      <nav
        id="primary-nav"
        className={menuOpen ? 'sidebar sidebar-open' : 'sidebar'}
        aria-label="Primary"
      >
        <ul>
          {NAV_ITEMS.map((item) => (
            <li key={item.to}>
              <NavLink to={item.to} end={item.to === '/'}>
                <span>{item.label}</span>
                {item.planned === true && <span className="nav-tag">Planned</span>}
              </NavLink>
            </li>
          ))}
        </ul>
        <p className="sidebar-note">Local instance · synthetic data only</p>
      </nav>

      <main id="main" className="main" tabIndex={-1}>
        <NoticeRegion />
        <Outlet />
      </main>
    </div>
  );
}
