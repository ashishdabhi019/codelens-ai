type Risk = 'low' | 'medium' | 'high' | 'critical';

const styles: Record<Risk, { dot: string; text: string; bg: string; border: string }> = {
  critical: { dot: '#f43f5e', text: '#fda4af', bg: 'rgba(244, 63, 94, 0.12)', border: 'rgba(244, 63, 94, 0.3)' },
  high:     { dot: '#fb923c', text: '#fed7aa', bg: 'rgba(251, 146, 60, 0.12)', border: 'rgba(251, 146, 60, 0.3)' },
  medium:   { dot: '#38bdf8', text: '#bae6fd', bg: 'rgba(56, 189, 248, 0.12)', border: 'rgba(56, 189, 248, 0.3)' },
  low:      { dot: '#4ade80', text: '#bbf7d0', bg: 'rgba(74, 222, 128, 0.12)', border: 'rgba(74, 222, 128, 0.3)' },
};

export function RiskBadge({ level }: { level: string }) {
  const s = styles[level.toLowerCase() as Risk] ?? styles.medium;
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
      RISK: {level.toUpperCase()}
    </span>
  );
}
