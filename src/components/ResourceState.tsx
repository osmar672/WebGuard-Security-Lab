import type { ReactNode } from 'react';
import type { Resource } from '../api/dashboardService';
import { EmptyState } from './EmptyState';

export function ResourceState<T>({
  resource,
  children,
  emptyTitle = 'No data available',
  emptyDescription = 'There are no records returned by the configured backend.',
}: {
  resource: Resource<T>;
  children: (data: T) => ReactNode;
  emptyTitle?: string;
  emptyDescription?: string;
}) {
  if (resource.kind === 'loading') return <div className="skeleton-line" aria-label="Loading" />;
  if (resource.kind === 'not-configured') return <EmptyState compact title="Not configured" description={resource.message} />;
  if (resource.kind === 'error') return <EmptyState compact title="Could not load data" description={resource.message} />;
  if (Array.isArray(resource.data) && resource.data.length === 0) return <EmptyState compact title={emptyTitle} description={emptyDescription} />;
  return <>{children(resource.data)}</>;
}
