import { Sidebar } from './Sidebar';
import { Outlet } from 'react-router-dom';

export function Layout() {
  return (
    <div style={{
      display: 'flex',
      height: '100vh',
      width: '100vw',
      overflow: 'hidden',
      background: '#000000',
      color: '#ffffff',
    }}>
      <Sidebar />
      <main style={{
        flex: 1,
        height: '100vh',
        overflowY: 'auto',
        overflowX: 'hidden',
        minWidth: 0,
        background: '#000000',
      }}>
        <Outlet />
      </main>
    </div>
  );
}
