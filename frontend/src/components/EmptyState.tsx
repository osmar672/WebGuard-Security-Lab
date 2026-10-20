import { Cable, FileSearch } from 'lucide-react';

export function EmptyState({
  title,
  description,
  compact = false,
}: {
  title: string;
  description: string;
  compact?: boolean;
}) {
  const Icon = compact ? Cable : FileSearch;
  return (
    <div className={`empty-state${compact ? ' empty-state--compact' : ''}`}>
      <div className="empty-state__icon"><Icon size={compact ? 18 : 22} aria-hidden="true" /></div>
      <div>
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}
