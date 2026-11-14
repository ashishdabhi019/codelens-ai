import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { getReviews, extractErrorMessage } from '../services/api';
import type { ReviewHistoryItem } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { RiskBadge } from '../components/RiskBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';
import { useToast } from '../context/ToastContext';
import { Plus, Terminal, AlertTriangle, ShieldAlert, ArrowRight } from 'lucide-react';

export function Dashboard() {
  const [reviews, setReviews] = useState<ReviewHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const toast = useToast();

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    getReviews()
      .then(setReviews)
      .catch(err => {
        const msg = extractErrorMessage(err);
        setError(msg);
        toast.error(msg, 'Dashboard Sync Failed');
      })
      .finally(() => setLoading(false));
  }, [toast]);

  useEffect(() => {
    loadData();
  }, []);

  const totalIssues = reviews.reduce((s, r) => s + r.findings_count, 0);
  const criticalCount = reviews.filter(r => r.risk_level === 'critical').length;

  const stats = [
    { label: 'TOTAL REVIEWS', value: reviews.length, icon: Terminal, color: '#ffffff' },
    { label: 'ISSUES DETECTED', value: totalIssues, icon: AlertTriangle, color: '#fb923c' },
    { label: 'CRITICAL ISSUES', value: criticalCount, icon: ShieldAlert, color: '#f43f5e' },
  ];

  return (
    <div style={{ padding: '32px 44px', width: '100%', boxSizing: 'border-box', color: '#ffffff' }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: '32px',
        paddingBottom: '24px',
        borderBottom: '1px solid #1f1f23',
        flexWrap: 'wrap',
        gap: '16px',
        width: '100%',
      }}>
        <div>
          <h1 style={{ color: '#ffffff', fontSize: '24px', fontWeight: 700, margin: '0 0 6px 0', letterSpacing: '-0.02em' }}>
            AI Code Review
          </h1>
          <p style={{ color: '#a1a1aa', fontSize: '13px', margin: 0, lineHeight: '1.5' }}>
            Review code changes, identify risks, and improve code quality with AI.
          </p>
        </div>

        <button
          onClick={() => navigate('/review/new')}
          style={{
            background: '#ffffff',
            color: '#000000',
            border: 'none',
            borderRadius: '6px',
            padding: '10px 20px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            boxShadow: '0 2px 8px rgba(255, 255, 255, 0.1)',
            transition: 'background 0.12s ease',
          }}
          onMouseEnter={e => e.currentTarget.style.background = '#e4e4e7'}
          onMouseLeave={e => e.currentTarget.style.background = '#ffffff'}
        >
          <Plus size={16} strokeWidth={2.5} />
          Start New Review
        </button>
      </div>

      {error && (
        <div style={{ marginBottom: '24px' }}>
          <ErrorBanner
            title="Service Unavailable"
            message={error}
            onDismiss={() => setError(null)}
            onRetry={loadData}
          />
        </div>
      )}

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: '16px',
        marginBottom: '36px',
        width: '100%',
      }}>
        {stats.map(s => {
          const Icon = s.icon;
          return (
            <div
              key={s.label}
              style={{
                background: '#0c0c0e',
                border: '1px solid #1f1f23',
                borderRadius: '8px',
                padding: '20px 22px',
                boxShadow: '0 2px 4px rgba(0, 0, 0, 0.4)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                <span style={{ color: '#71717a', fontSize: '11px', letterSpacing: '0.05em', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace' }}>
                  {s.label}
                </span>
                <Icon size={16} color={s.color} />
              </div>
              <div style={{ color: '#ffffff', fontSize: '32px', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
                {loading ? <LoadingSpinner size={22} /> : s.value}
              </div>
            </div>
          );
        })}
      </div>

      <div style={{ width: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <h2 style={{ color: '#ffffff', fontSize: '15px', fontWeight: 600, margin: 0, letterSpacing: '0.02em' }}>
            RECENT REVIEWS
          </h2>
          {reviews.length > 0 && (
            <button
              onClick={() => navigate('/history')}
              style={{
                background: 'none',
                border: 'none',
                color: '#ffffff',
                fontSize: '12px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                fontWeight: 500,
              }}
            >
              view all ({reviews.length})
              <ArrowRight size={12} />
            </button>
          )}
        </div>

        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '60px' }}>
            <LoadingSpinner size={26} />
          </div>
        ) : reviews.length === 0 ? (
          <div style={{
            background: '#0c0c0e',
            border: '1px dashed #1f1f23',
            borderRadius: '8px',
            padding: '48px 24px',
            textAlign: 'center',
            color: '#71717a',
            fontSize: '13px',
          }}>
            No reviews yet. Start by analyzing a Git diff or patch.
          </div>
        ) : (
          <div style={{
            background: '#0c0c0e',
            border: '1px solid #1f1f23',
            borderRadius: '8px',
            overflow: 'hidden',
            boxShadow: '0 2px 4px rgba(0, 0, 0, 0.4)',
            width: '100%',
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1f1f23', color: '#71717a', fontSize: '11px', background: '#121215', fontFamily: 'JetBrains Mono, monospace' }}>
                  <th style={{ padding: '14px 18px' }}>STATUS</th>
                  <th style={{ padding: '14px 18px' }}>FILE</th>
                  <th style={{ padding: '14px 18px' }}>RISK</th>
                  <th style={{ padding: '14px 18px' }}>ISSUES</th>
                  <th style={{ padding: '14px 18px' }}>DATE</th>
                  <th style={{ padding: '14px 18px' }}></th>
                </tr>
              </thead>
              <tbody>
                {reviews.slice(0, 8).map(r => (
                  <tr
                    key={r.id}
                    onClick={() => navigate(`/review/${r.id}`)}
                    style={{
                      borderBottom: '1px solid #18181c',
                      cursor: 'pointer',
                      transition: 'background 0.1s ease',
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = '#151518'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td style={{ padding: '14px 18px' }}>
                      <StatusBadge status={r.overall_status} />
                    </td>
                    <td style={{ padding: '14px 18px', color: '#ffffff' }}>
                      <code style={{
                        color: '#ffffff',
                        fontSize: '12px',
                        background: '#18181b',
                        padding: '3px 8px',
                        borderRadius: '4px',
                        border: '1px solid #27272a',
                        fontFamily: 'JetBrains Mono, monospace',
                      }}>
                        {r.filename ?? 'stdin.diff'}
                      </code>
                    </td>
                    <td style={{ padding: '14px 18px' }}>
                      <RiskBadge level={r.risk_level} />
                    </td>
                    <td style={{ padding: '14px 18px', color: '#ffffff', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace' }}>
                      {r.findings_count}
                    </td>
                    <td style={{ padding: '14px 18px', color: '#71717a', fontSize: '12px' }}>
                      {new Date(r.created_at).toLocaleDateString()}
                    </td>
                    <td style={{ padding: '14px 18px', textAlign: 'right' }}>
                      <span style={{ color: '#ffffff', fontSize: '12px', fontWeight: 500 }}>inspect &rarr;</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
