import { useState } from 'react';
import type { Finding } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { ChevronDown, ChevronRight, FileCode, Copy, Check } from 'lucide-react';
import { useToast } from '../context/ToastContext';

const severityBorders: Record<string, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#38bdf8',
  low: '#4ade80',
};

export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const toast = useToast();
  const borderLeftColor = severityBorders[finding.severity] ?? '#27272a';

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!finding.suggested_fix) return;
    navigator.clipboard.writeText(finding.suggested_fix).then(() => {
      setCopied(true);
      toast.success(
        `Fix for "${finding.title}" copied to clipboard`,
        'Copied to Clipboard'
      );
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      toast.error('Failed to copy to clipboard');
    });
  };

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
        {finding.id && (
          <span style={{
            color: '#a1a1aa',
            fontSize: '10.5px',
            fontFamily: 'JetBrains Mono, monospace',
            background: '#18181b',
            padding: '1px 6px',
            borderRadius: '4px',
            border: '1px solid #27272a',
          }}>
            #{finding.id}
          </span>
        )}
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

      {finding.root_cause && (
        <div style={{ marginBottom: '8px', fontSize: '12px', color: '#e4e4e7', background: '#141418', padding: '6px 10px', borderRadius: '4px', border: '1px solid #222226' }}>
          <strong style={{ color: '#fb923c', fontSize: '10.5px', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>Root Cause: </strong>
          {finding.root_cause}
        </div>
      )}

      {finding.evidence && (
        <div style={{ marginBottom: '10px' }}>
          <div style={{ fontSize: '10px', textTransform: 'uppercase', color: '#71717a', fontFamily: 'JetBrains Mono, monospace', marginBottom: '3px' }}>
            Code Evidence
          </div>
          <pre style={{
            background: '#09090c',
            border: '1px solid #27272a',
            padding: '6px 10px',
            borderRadius: '4px',
            margin: 0,
            fontSize: '11.5px',
            color: '#f87171',
            fontFamily: 'JetBrains Mono, monospace',
            overflowX: 'auto',
          }}>
            <code>{finding.evidence}</code>
          </pre>
        </div>
      )}

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
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: expanded ? '6px' : '0' }}>
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
              {finding.fix_verification_status === 'validated_syntax' && (
                <span style={{
                  fontSize: '9.5px',
                  color: '#4ade80',
                  background: 'rgba(74, 222, 128, 0.12)',
                  border: '1px solid rgba(74, 222, 128, 0.3)',
                  padding: '1px 5px',
                  borderRadius: '3px',
                  fontFamily: 'JetBrains Mono, monospace',
                  marginLeft: '4px',
                }}>
                  Validated
                </span>
              )}
              {finding.fix_verification_status === 'proposed' && (
                <span style={{
                  fontSize: '9.5px',
                  color: '#fbbf24',
                  background: 'rgba(251, 191, 36, 0.12)',
                  border: '1px solid rgba(251, 191, 36, 0.3)',
                  padding: '1px 5px',
                  borderRadius: '3px',
                  fontFamily: 'JetBrains Mono, monospace',
                  marginLeft: '4px',
                }}>
                  Proposed
                </span>
              )}
            </button>

            {expanded && (
              <button
                type="button"
                onClick={handleCopy}
                style={{
                  background: '#161b22',
                  border: '1px solid #30363d',
                  borderRadius: '4px',
                  color: copied ? '#4ade80' : '#8b949e',
                  fontSize: '11px',
                  padding: '3px 8px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  fontFamily: "'Inter', sans-serif",
                  transition: 'all 0.12s ease',
                }}
              >
                {copied ? <Check size={12} color="#4ade80" /> : <Copy size={12} />}
                <span>{copied ? 'Copied fix!' : 'Copy fix'}</span>
              </button>
            )}
          </div>
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
