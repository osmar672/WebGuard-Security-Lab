import type { ReactNode } from 'react';
import { ArrowUpRight } from 'lucide-react';
import { StatusPill, type StatusTone } from './StatusPill';

export function MetricCard({
  label,
  value,
  description,
  icon,
  kind,
  status,
  tone,
}: {
  label: string;
  value: string;
  description: string;
  icon: ReactNode;
  kind?: 'status' | 'metric';
  status?: string;
  tone?: StatusTone;
}) {
  return (
    <article className="metric-card">
      <div className="metric-card__top"><span className="metric-card__label">{label}</span><span className="metric-card__icon">{icon}</span></div>
      <div className={`metric-card__value${kind === 'status' ? ' metric-card__value--status' : ''}`}>{kind === 'status' && status ? <StatusPill status={status} tone={tone} /> : value}</div>
      <div className="metric-card__bottom"><span>{description}</span><ArrowUpRight size={15} aria-hidden="true" /></div>
    </article>
  );
}
