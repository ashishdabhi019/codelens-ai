type Severity = 'critical' | 'high' | 'medium' | 'low';

const styles: Record<Severity, { dot: string; text: string; bg: string; border: string }> = {
  critical: { dot: '#f43f5e', text: '#fda4af', bg: 'rgba(244, 63, 94, 0.1)', border: 'rgba(244, 63, 94, 0.25)' },
  high:     { dot: '#fb923c', text: '#fed7aa', bg: 'rgba(251, 146, 60, 0.1)', border: 'rgba(251, 146, 60, 0.25)' },
  medium:   { dot: '#38bdf8', text: '#bae6fd', bg: 'rgba(56, 189, 248, 0.1)', border: 'rgba(56, 189, 248, 0.25)' },
  low:      { dot: '#4ade80', text: '#bbf7d0', bg: 'rgba(74, 222, 128, 0.1)', border: 'rgba(74, 222, 128, 0.25)' },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const s = styles[severity.toLowerCase() as Severity] ?? styles.low;
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      padding: '2px 8px',
      borderRadius: '4px',
      fontSize: '11px',
      fontWeight: 600,
      letterSpacing: '0.04em',
      color: s.text,
      border: `1px solid ${s.border}`,
      background: s.bg,
      fontFamily: 'JetBrains Mono, monospace',
    }}>
      <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: s.dot }} />
      {severity.toUpperCase()}
    </span>
  );
}
