type Status = 'approved' | 'changes_requested' | 'needs_attention';

const styles: Record<Status, { dot: string; label: string; text: string; bg: string; border: string }> = {
  approved: {
    dot: '#4ade80',
    label: 'APPROVED',
    text: '#bbf7d0',
    bg: 'rgba(74, 222, 128, 0.08)',
    border: 'rgba(74, 222, 128, 0.25)',
  },
  changes_requested: {
    dot: '#f43f5e',
    label: 'CHANGES REQUESTED',
    text: '#fda4af',
    bg: 'rgba(244, 63, 94, 0.08)',
    border: 'rgba(244, 63, 94, 0.25)',
  },
  needs_attention: {
    dot: '#fb923c',
    label: 'NEEDS ATTENTION',
    text: '#fed7aa',
    bg: 'rgba(251, 146, 60, 0.08)',
    border: 'rgba(251, 146, 60, 0.25)',
  },
};

export function StatusBadge({ status }: { status: string }) {
  const s = styles[status as Status] ?? styles.needs_attention;
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      padding: '3px 10px',
      borderRadius: '5px',
      fontSize: '11px',
      fontWeight: 600,
      letterSpacing: '0.04em',
      color: s.text,
      border: `1px solid ${s.border}`,
      background: s.bg,
      fontFamily: 'JetBrains Mono, monospace',
    }}>
      <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: s.dot }} />
      {s.label}
    </span>
  );
}
