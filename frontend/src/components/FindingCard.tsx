import { useState } from 'react';
import type { Finding } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { ChevronDown, ChevronRight, FileCode } from 'lucide-react';

const severityBorders: Record<string, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#38bdf8',
  low: '#4ade80',
};

export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  const borderLeftColor = severityBorders[finding.severity] ?? '#27272a';

  return (
    <div style={{
      background: '#0c0c0e',
      border: '1px solid #1f1f23',
      borderLeft: `3px solid ${borderLeftColor}`,
      borderRadius: '6px',
      padding: '16px',
      marginBottom: '12px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.4)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', flexWrap: 'wrap' }}>
        <SeverityBadge severity={finding.severity} />
        <span style={{
          color: '#a1a1aa',
          fontSize: '11px',
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
          fontFamily: 'JetBrains Mono, monospace',
        }}>
          {finding.category}
        </span>
        <span style={{ color: '#ffffff', fontWeight: 600, fontSize: '13px', flex: 1, minWidth: '120px' }}>
          {finding.title}
        </span>
        <span style={{ color: '#71717a', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
          {Math.round(finding.confidence * 100)}% conf
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '10px' }}>
        <FileCode size={13} color="#a1a1aa" />
        <code style={{
          fontSize: '11px',
          color: '#e4e4e7',
          background: '#18181b',
          padding: '2px 6px',
          borderRadius: '3px',
          border: '1px solid #27272a',
          fontFamily: 'JetBrains Mono, monospace',
        }}>
          {finding.file}{finding.line != null ? `:${finding.line}` : ''}
        </code>
      </div>

      <p style={{ color: '#d4d4d8', fontSize: '13px', lineHeight: '1.6', margin: '0 0 12px 0' }}>
        {finding.description}
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '10px', marginBottom: finding.suggested_fix ? '10px' : '0' }}>
        <div style={{ background: '#121215', border: '1px solid #222227', borderRadius: '5px', padding: '10px 12px' }}>
          <div style={{ color: '#fb923c', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
            Impact
          </div>
          <div style={{ color: '#a1a1aa', fontSize: '12px', lineHeight: '1.5' }}>
            {finding.impact}
          </div>
        </div>

        <div style={{ background: '#121215', border: '1px solid #222227', borderRadius: '5px', padding: '10px 12px' }}>
          <div style={{ color: '#ffffff', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
            Recommendation
          </div>
          <div style={{ color: '#a1a1aa', fontSize: '12px', lineHeight: '1.5' }}>
            {finding.recommendation}
          </div>
        </div>
      </div>

      {finding.suggested_fix && (
        <div style={{ marginTop: '10px' }}>
          <button
            onClick={() => setExpanded(!expanded)}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: '#ffffff',
              fontSize: '12px',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              padding: '2px 0',
              fontWeight: 600,
            }}
          >
            {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
            <span>Suggested Fix</span>
          </button>
          {expanded && (
            <pre style={{
              margin: '8px 0 0',
              background: '#000000',
              border: '1px solid #27272a',
              borderRadius: '5px',
              padding: '12px 14px',
              fontSize: '11px',
              color: '#f4f4f5',
              overflowX: 'auto',
              lineHeight: '1.6',
              fontFamily: 'JetBrains Mono, monospace',
            }}>
              <code>{finding.suggested_fix}</code>
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
