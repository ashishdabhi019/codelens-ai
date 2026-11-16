import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getReview, extractErrorMessage } from '../services/api';
import type { ReviewResponse, Finding } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { RiskBadge } from '../components/RiskBadge';
import { FindingCard } from '../components/FindingCard';
import { InlineCodeReview } from '../components/InlineCodeReview';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';
import { useToast } from '../context/ToastContext';
import { Copy, Download, Plus, AlertTriangle, CheckCircle, Check, Code2, LayoutList } from 'lucide-react';

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function ReviewResults() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const [review, setReview] = useState<ReviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<SeverityFilter>('all');
  const [viewMode, setViewMode] = useState<'inline' | 'cards'>('inline');
  const [copied, setCopied] = useState(false);

  const fetchReview = useCallback((reviewId: string) => {
    setLoading(true);
    setError(null);
    getReview(reviewId)
      .then(setReview)
      .catch(err => {
        const msg = extractErrorMessage(err);
        setError(msg);
        toast.error(msg, 'Failed to Load Review');
      })
      .finally(() => setLoading(false));
  }, [toast]);

  useEffect(() => {
    if (id) fetchReview(id);
  }, [id, fetchReview]);

  const sortedFindings = useCallback((findings: Finding[]) =>
    [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)),
    []
  );

  const filteredFindings = useCallback((findings: Finding[]) => {
    const sorted = sortedFindings(findings);
    if (filter === 'all') return sorted;
    return sorted.filter(f => f.severity === filter);
  }, [filter, sortedFindings]);

  const handleCopyReport = useCallback(() => {
    if (!review) return;
    const lines = [
      `CodeLens AI — Code Review Report`,
      `Timestamp: ${new Date(review.created_at).toISOString()}`,
      `Status: ${review.result.overall_status.toUpperCase()} | Risk: ${review.result.risk_level.toUpperCase()}`,
      `Files: ${review.result.files_reviewed} | Findings: ${review.result.findings.length}`,
      ``,
      `SUMMARY:`,
      review.result.summary,
      ``,
      `FINDINGS:`,
    ];
    review.result.findings.forEach((f, i) => {
      lines.push(`${i + 1}. [${f.severity.toUpperCase()}] ${f.title} (${f.file}${f.line != null ? `:${f.line}` : ''})`);
      lines.push(`   Description: ${f.description}`);
      lines.push(`   Impact: ${f.impact}`);
      lines.push(`   Fix: ${f.recommendation}`);
      if (f.suggested_fix) {
        lines.push(`   Suggested Code:\n${f.suggested_fix}`);
      }
      lines.push('');
    });
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setCopied(true);
      toast.success('Review report copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      toast.error('Could not copy report to clipboard');
    });
  }, [review, toast]);

  const handleDownload = useCallback(() => {
    if (!review) return;
    try {
      const blob = new Blob([JSON.stringify(review, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `codelens-review-${review.id.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported codelens-review-${review.id.slice(0, 8)}.json`);
    } catch {
      toast.error('Failed to download review report');
    }
  }, [review, toast]);

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <div style={{ textAlign: 'center' }}>
          <LoadingSpinner size={32} />
          <p style={{ color: '#a1a1aa', fontSize: '13px', marginTop: '16px', letterSpacing: '0.02em' }}>
            executing agent review pipeline...
          </p>
        </div>
      </div>
    );
  }

  if (error || !review) {
    return (
      <div style={{ padding: '32px 44px', maxWidth: '700px' }}>
        <ErrorBanner
          title="Review Fetch Failed"
          message={error ?? 'Review report not found in SQLite database.'}
          onRetry={id ? () => fetchReview(id) : undefined}
        />
        <button
          onClick={() => navigate('/review/new')}
          style={{
            marginTop: '16px',
            background: '#ffffff',
            color: '#000000',
            border: 'none',
            borderRadius: '5px',
            padding: '9px 18px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          New Review
        </button>
      </div>
    );
  }

  const { result } = review;
  const allFindings = result.findings;
  const displayed = filteredFindings(allFindings);

  const actionBtnStyle: React.CSSProperties = {
    background: '#121215',
    color: '#ffffff',
    border: '1px solid #27272a',
    borderRadius: '5px',
    padding: '8px 16px',
    fontSize: '12px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    fontFamily: 'inherit',
    fontWeight: 500,
    transition: 'all 0.12s ease',
  };

  return (
    <div style={{ padding: '32px 44px', width: '100%', boxSizing: 'border-box', color: '#ffffff' }}>
      <div style={{
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px',
        marginBottom: '28px',
        paddingBottom: '20px',
        borderBottom: '1px solid #1f1f23',
        width: '100%',
      }}>
        <div>
          <h1 style={{ color: '#ffffff', fontSize: '24px', fontWeight: 700, margin: '0 0 10px 0', letterSpacing: '-0.02em' }}>
            Review Report
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <StatusBadge status={result.overall_status} />
            <RiskBadge level={result.risk_level} />
            <span style={{ color: '#71717a', fontSize: '12px', fontFamily: 'JetBrains Mono, monospace' }}>
              {result.files_reviewed} file{result.files_reviewed !== 1 ? 's' : ''}
            </span>
            <span style={{ color: '#3f3f46', fontSize: '12px' }}>•</span>
            <span style={{ color: '#71717a', fontSize: '12px', fontFamily: 'JetBrains Mono, monospace' }}>
              {allFindings.length} finding{allFindings.length !== 1 ? 's' : ''}
            </span>
            <span style={{ color: '#3f3f46', fontSize: '12px' }}>•</span>
            <span style={{ color: '#ffffff', fontSize: '12px', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace' }}>
              {review.processing_time_seconds.toFixed(2)}s
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button onClick={handleCopyReport} style={actionBtnStyle}>
            {copied ? <Check size={14} color="#4ade80" /> : <Copy size={14} />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
          <button onClick={handleDownload} style={actionBtnStyle}>
            <Download size={14} />
            <span>JSON</span>
          </button>
          <button
            onClick={() => navigate('/review/new')}
            style={{
              ...actionBtnStyle,
              background: '#ffffff',
              color: '#000000',
              border: 'none',
              fontWeight: 600,
              boxShadow: '0 2px 6px rgba(255, 255, 255, 0.1)',
            }}
            onMouseEnter={e => e.currentTarget.style.background = '#e4e4e7'}
            onMouseLeave={e => e.currentTarget.style.background = '#ffffff'}
          >
            <Plus size={14} strokeWidth={2.5} />
            <span>New</span>
          </button>
        </div>
      </div>

      {(!result.llm_available || result.partial_analysis) && (
        <div style={{
          background: 'rgba(245, 158, 11, 0.08)',
          border: '1px solid rgba(245, 158, 11, 0.3)',
          borderRadius: '7px',
          padding: '10px 14px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          fontSize: '12px',
          marginBottom: '20px',
          width: '100%',
          boxSizing: 'border-box',
          color: '#fbbf24',
        }}>
          <AlertTriangle size={15} color="#fbbf24" style={{ flexShrink: 0 }} />
          <span>
            <strong style={{ color: '#ffffff' }}>Partial Review:</strong> LLM semantic analysis was offline or unreachable. Review completed with deterministic AST static rules.
          </span>
        </div>
      )}

      <div style={{
        background: '#0c0c0e',
        border: '1px solid #1f1f23',
        borderRadius: '8px',
        padding: '20px 24px',
        marginBottom: '24px',
        boxShadow: '0 2px 4px rgba(0, 0, 0, 0.4)',
        width: '100%',
        boxSizing: 'border-box',
      }}>
        <div style={{ color: '#71717a', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
          SUMMARY
        </div>
        <p style={{ color: '#e4e4e7', fontSize: '14px', lineHeight: '1.6', margin: 0 }}>
          {result.summary}
        </p>
      </div>

      {/* View Mode Switcher + Severity Filters */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px',
        marginBottom: '20px',
        width: '100%',
      }}>
        {/* Severity Filter Pills */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {(['all', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map(f => {
            const active = filter === f;
            const count = f === 'all' ? allFindings.length : allFindings.filter(x => x.severity === f).length;
            return (
              <button
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  padding: '6px 13px',
                  borderRadius: '5px',
                  border: `1px solid ${active ? '#ffffff' : '#1f1f23'}`,
                  background: active ? '#ffffff' : '#0c0c0e',
                  color: active ? '#000000' : '#a1a1aa',
                  fontSize: '11px',
                  cursor: 'pointer',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontWeight: active ? 700 : 500,
                  transition: 'all 0.12s ease',
                }}
              >
                {f.toUpperCase()} ({count})
              </button>
            );
          })}
        </div>

        {/* Layout View Toggle (Inline Code View vs Cards View) */}
        {review.diff_content && (
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            background: '#121216',
            border: '1px solid #222228',
            borderRadius: '6px',
            padding: '3px',
            gap: '3px',
          }}>
            <button
              type="button"
              onClick={() => setViewMode('inline')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '5px 11px',
                borderRadius: '4px',
                background: viewMode === 'inline' ? '#22222a' : 'transparent',
                color: viewMode === 'inline' ? '#ffffff' : '#8e8e93',
                border: 'none',
                fontSize: '11.5px',
                fontWeight: viewMode === 'inline' ? 600 : 500,
                cursor: 'pointer',
                fontFamily: "'Inter', sans-serif",
                transition: 'all 0.12s ease',
              }}
            >
              <Code2 size={13} color={viewMode === 'inline' ? '#ffffff' : '#71717a'} />
              <span>Inline Code Review</span>
            </button>

            <button
              type="button"
              onClick={() => setViewMode('cards')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '5px 11px',
                borderRadius: '4px',
                background: viewMode === 'cards' ? '#22222a' : 'transparent',
                color: viewMode === 'cards' ? '#ffffff' : '#8e8e93',
                border: 'none',
                fontSize: '11.5px',
                fontWeight: viewMode === 'cards' ? 600 : 500,
                cursor: 'pointer',
                fontFamily: "'Inter', sans-serif",
                transition: 'all 0.12s ease',
              }}
            >
              <LayoutList size={13} color={viewMode === 'cards' ? '#ffffff' : '#71717a'} />
              <span>All Findings Cards</span>
            </button>
          </div>
        )}
      </div>

      {/* Primary Content: Inline Code Window with Review Comments */}
      {viewMode === 'inline' && review.diff_content ? (
        <InlineCodeReview
          diffContent={review.diff_content}
          filename={review.filename || 'source.py'}
          findings={displayed}
        />
      ) : (
        /* Cards View */
        displayed.length === 0 ? (
          allFindings.length === 0 ? (
            <div style={{
              background: 'rgba(74, 222, 128, 0.04)',
              border: '1px solid rgba(74, 222, 128, 0.22)',
              borderRadius: '8px',
              padding: '36px 24px',
              textAlign: 'center',
              marginBottom: '28px',
              width: '100%',
              boxSizing: 'border-box',
            }}>
              <div style={{
                width: '36px',
                height: '36px',
                borderRadius: '50%',
                background: 'rgba(74, 222, 128, 0.12)',
                border: '1px solid rgba(74, 222, 128, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 12px auto',
              }}>
                <CheckCircle size={18} color="#4ade80" />
              </div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#ffffff', marginBottom: '4px' }}>
                All Security & Quality Checks Passed
              </div>
              <div style={{ fontSize: '12.5px', color: '#9ca3af', maxWidth: '440px', margin: '0 auto', lineHeight: '1.5' }}>
                No critical bugs, syntax defects, or security vulnerabilities detected in this file.
              </div>
            </div>
          ) : (
            <div style={{
              background: '#0c0c0e',
              border: '1px dashed #1f1f23',
              borderRadius: '8px',
              padding: '36px',
              textAlign: 'center',
              color: '#71717a',
              fontSize: '13px',
              width: '100%',
              boxSizing: 'border-box',
              marginBottom: '28px',
            }}>
              No findings match "{filter.toUpperCase()}" filter.
            </div>
          )
        ) : (
          <div style={{ marginBottom: '28px', width: '100%' }}>
            {displayed.map((f, i) => (
              <FindingCard key={`${f.file}-${f.title}-${i}`} finding={f} />
            ))}
          </div>
        )
      )}

      {result.missing_tests.length > 0 && (
        <div style={{
          background: 'rgba(251, 146, 60, 0.06)',
          border: '1px solid rgba(251, 146, 60, 0.25)',
          borderRadius: '8px',
          padding: '20px 24px',
          marginBottom: '20px',
          width: '100%',
          boxSizing: 'border-box',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <AlertTriangle size={16} color="#fb923c" />
            <span style={{ color: '#fed7aa', fontSize: '12px', letterSpacing: '0.04em', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
              MISSING TEST COVERAGE
            </span>
          </div>
          <ul style={{ margin: 0, paddingLeft: '20px', color: '#fed7aa', fontSize: '13px', lineHeight: '1.6' }}>
            {result.missing_tests.map((t, i) => (
              <li key={i}>{t}</li>
            ))}
          </ul>
        </div>
      )}

      {result.positive_observations.length > 0 && (
        <div style={{
          background: 'rgba(74, 222, 128, 0.06)',
          border: '1px solid rgba(74, 222, 128, 0.25)',
          borderRadius: '8px',
          padding: '20px 24px',
          width: '100%',
          boxSizing: 'border-box',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <CheckCircle size={16} color="#4ade80" />
            <span style={{ color: '#bbf7d0', fontSize: '12px', letterSpacing: '0.04em', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
              POSITIVE OBSERVATIONS
            </span>
          </div>
          <ul style={{ margin: 0, paddingLeft: '20px', color: '#bbf7d0', fontSize: '13px', lineHeight: '1.6' }}>
            {result.positive_observations.map((o, i) => (
              <li key={i}>{o}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
