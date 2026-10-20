import { useEffect, useState } from 'react';
import { BrowserRouter, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom';
import { getAccessToken } from './api/session';
import { AppShell } from './components/AppShell';
import { DashboardPage } from './pages/DashboardPage';
import { FindingsPage } from './pages/FindingsPage';
import { HistoryPage } from './pages/HistoryPage';
import { LoginPage } from './pages/LoginPage';
import { ModulePage } from './pages/ModulePage';
import { TargetsPage } from './pages/TargetsPage';
import { SettingsPage } from './pages/SettingsPage';
import { AIAssistantPage } from './pages/AIAssistantPage';
import { ToolCenterPage } from './pages/ToolCenterPage';
import { ReportsPage } from './pages/ReportsPage';

function AuthenticatedRoutes() {
  const [authenticated, setAuthenticated] = useState(() => Boolean(getAccessToken()));
  const location = useLocation();

  useEffect(() => {
    const onUnauthorized = () => setAuthenticated(false);
    window.addEventListener('webguard:unauthorized', onUnauthorized);
    return () => window.removeEventListener('webguard:unauthorized', onUnauthorized);
  }, []);

  if (!authenticated) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <Outlet />;
}

export function App() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<AuthenticatedRoutes />}>
          <Route element={<AppShell />}>
            <Route index element={<DashboardPage />} />
            <Route path="targets" element={<TargetsPage />} />
            <Route path="tools" element={<ToolCenterPage />} />
            <Route path="scanner" element={<ToolCenterPage category="web_security" />} />
            <Route path="browser-bots" element={<ToolCenterPage category="browser" />} />
            <Route path="load-tests" element={<ToolCenterPage category="performance" />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="ai-assistant" element={<AIAssistantPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="history" element={<HistoryPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
