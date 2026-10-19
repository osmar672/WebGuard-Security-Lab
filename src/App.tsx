import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { DashboardPage } from './pages/DashboardPage';
import { ModulePage } from './pages/ModulePage';
import { SettingsPage } from './pages/SettingsPage';

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="targets" element={<ModulePage />} />
          <Route path="scanner" element={<ModulePage />} />
          <Route path="browser-bots" element={<ModulePage />} />
          <Route path="load-tests" element={<ModulePage />} />
          <Route path="findings" element={<ModulePage />} />
          <Route path="reports" element={<ModulePage />} />
          <Route path="history" element={<ModulePage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
