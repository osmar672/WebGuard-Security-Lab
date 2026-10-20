import { CheckCircle2, CircleDashed, CircleX, Clock3, AlertTriangle } from 'lucide-react';

export type StatusTone = 'success' | 'warning' | 'danger' | 'neutral' | 'info';

const toneByStatus = (status: string): StatusTone => {
  const normalized = status.toLowerCase();
  if (['healthy', 'ok', 'operational', 'completed', 'approved', 'ready', 'available'].includes(normalized)) return 'success';
  if (['degraded', 'warning', 'queued', 'pending'].includes(normalized)) return 'warning';
  if (['failed', 'error', 'denied', 'unavailable'].includes(normalized)) return 'danger';
  if (['running'].includes(normalized)) return 'info';
  return 'neutral';
};

export function StatusPill({ status, tone }: { status: string; tone?: StatusTone }) {
  const resolvedTone = tone ?? toneByStatus(status);
  const Icon = resolvedTone === 'success' ? CheckCircle2
    : resolvedTone === 'warning' ? AlertTriangle
      : resolvedTone === 'danger' ? CircleX
        : resolvedTone === 'info' ? Clock3 : CircleDashed;
  return <span className={`status-pill status-pill--${resolvedTone}`}><Icon size={13} aria-hidden="true" />{status}</span>;
}
