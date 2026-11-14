import { NavLink, Link } from 'react-router-dom';
import { Terminal, Plus, History, Settings } from 'lucide-react';

const items = [
  { to: '/', label: 'Overview', icon: Terminal, end: true },
  { to: '/review/new', label: 'New Review', icon: Plus, end: false },
  { to: '/history', label: 'History', icon: History, end: false },
  { to: '/settings', label: 'Settings', icon: Settings, end: false },
];

export function Sidebar() {
  return (
    <aside style={{
      width: '240px',
      height: '100vh',
      background: '#09090b',
      borderRight: '1px solid #1f1f23',
      display: 'flex',
      flexDirection: 'column',
      flexShrink: 0,
      userSelect: 'none',
      position: 'sticky',
      top: 0,
      left: 0,
      zIndex: 20,
    }}>
      <div style={{ padding: '22px 20px', borderBottom: '1px solid #1f1f23' }}>
        <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '11px', textDecoration: 'none' }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '7px',
            background: '#ffffff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            boxShadow: '0 2px 8px rgba(255, 255, 255, 0.12)',
          }}>
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path
                d="M4 4.5L9 9L4 13.5"
                stroke="#000000"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <line
                x1="10.5"
                y1="13.5"
                x2="14.5"
                y2="13.5"
                stroke="#000000"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
          </div>
          <div>
            <div style={{ color: '#ffffff', fontWeight: 700, fontSize: '14px', letterSpacing: '-0.02em' }}>
              CodeLens<span style={{ color: '#71717a' }}>.ai</span>
            </div>
            <div style={{ color: '#71717a', fontSize: '11px', fontWeight: 400 }}>code review agent</div>
          </div>
        </Link>
      </div>

      <nav style={{ padding: '12px 10px', flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {items.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <Icon size={15} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div style={{
        padding: '14px 20px',
        borderTop: '1px solid #1f1f23',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        fontSize: '11px',
        color: '#71717a',
      }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#22c55e', display: 'inline-block' }} />
          ready
        </span>
        <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>v1.0.0</span>
      </div>
    </aside>
  );
}
