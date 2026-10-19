import {
  Activity, Bot, Bug, ClipboardList, FileText, Gauge, LayoutDashboard, Settings, ShieldCheck, Target,
  type LucideIcon,
} from 'lucide-react';

export interface NavigationItem {
  label: string;
  path: string;
  icon: LucideIcon;
  group: 'workspace' | 'operations' | 'insights' | 'system';
}

export const navigationItems: NavigationItem[] = [
  { label: 'Dashboard', path: '/', icon: LayoutDashboard, group: 'workspace' },
  { label: 'Targets', path: '/targets', icon: Target, group: 'workspace' },
  { label: 'Security Scanner', path: '/scanner', icon: ShieldCheck, group: 'operations' },
  { label: 'Browser Bots', path: '/browser-bots', icon: Bot, group: 'operations' },
  { label: 'Load Tests', path: '/load-tests', icon: Gauge, group: 'operations' },
  { label: 'Findings', path: '/findings', icon: Bug, group: 'insights' },
  { label: 'Reports', path: '/reports', icon: FileText, group: 'insights' },
  { label: 'History', path: '/history', icon: Activity, group: 'insights' },
  { label: 'Settings', path: '/settings', icon: Settings, group: 'system' },
];

export const pageCopy: Record<string, { title: string; eyebrow: string; description: string }> = {
  '/': { title: 'Security overview', eyebrow: 'Workspace / Dashboard', description: 'Your authorized assessment workspace at a glance.' },
  '/targets': { title: 'Targets', eyebrow: 'Workspace / Targets', description: 'Manage explicitly authorized hosts and assessment scope.' },
  '/scanner': { title: 'Security Scanner', eyebrow: 'Operations / Scanner', description: 'Security assessment jobs and scanner engine availability.' },
  '/browser-bots': { title: 'Browser Bots', eyebrow: 'Operations / Browser bots', description: 'Controlled browser automation for authorized targets.' },
  '/load-tests': { title: 'Load Tests', eyebrow: 'Operations / Load tests', description: 'Controlled performance tests with bounded execution limits.' },
  '/findings': { title: 'Findings', eyebrow: 'Insights / Findings', description: 'Review security findings returned by configured backend services.' },
  '/reports': { title: 'Reports', eyebrow: 'Insights / Reports', description: 'Exportable reports from completed backend jobs.' },
  '/history': { title: 'History', eyebrow: 'Insights / History', description: 'Audit events and recent activity from the backend.' },
  '/settings': { title: 'Settings', eyebrow: 'System / Settings', description: 'Frontend connection configuration and integration status.' },
};

export const groupLabels: Record<NavigationItem['group'], string> = {
  workspace: 'Workspace',
  operations: 'Operations',
  insights: 'Insights',
  system: 'System',
};
