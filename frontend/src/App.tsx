import { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ToastProvider } from './context/ToastContext';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { NewReview } from './pages/NewReview';
import { ReviewResults } from './pages/ReviewResults';
import { History } from './pages/History';
import { Settings } from './pages/Settings';

export default function App() {
  // Ensure the browser tab icon updates without cached borders
  useEffect(() => {
    const rawSvg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7.5' fill='%2309090b' stroke='none'/><path d='M7 7.5L15 16L7 24.5' stroke='%23ffffff' stroke-width='2.8' stroke-linecap='round' stroke-linejoin='round' fill='none'/><line x1='17.5' y1='24.5' x2='25' y2='24.5' stroke='%23ffffff' stroke-width='2.8' stroke-linecap='round'/></svg>`;
    const dataUri = `data:image/svg+xml,${encodeURIComponent(rawSvg)}`;
    let link = document.querySelector<HTMLLinkElement>("link[rel~='icon']");
    if (!link) {
      link = document.createElement('link');
      link.rel = 'icon';
      document.head.appendChild(link);
    }
    link.type = 'image/svg+xml';
    link.href = dataUri;
  }, []);

  return (
    <ToastProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/review/new" element={<NewReview />} />
            <Route path="/review/:id" element={<ReviewResults />} />
            <Route path="/history" element={<History />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ToastProvider>
  );
}
