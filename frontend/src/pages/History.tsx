import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getReviews, deleteReview, extractErrorMessage } from '../services/api';
import type { ReviewHistoryItem } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { RiskBadge } from '../components/RiskBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';
import { useToast } from '../context/ToastContext';
import { Trash2, Search, ExternalLink } from 'lucide-react';

export function History() {
  const navigate = useNavigate();
  const toast = useToast();
  const [reviews, setReviews] = useState<ReviewHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  const load = () => {
    setLoading(true);
    setError(null);
    getReviews()
      .then(setReviews)
      .catch(err => {
        const msg = extractErrorMessage(err);
        setError(msg);
        toast.error(msg, 'History Error');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Delete this review record from SQLite database?')) return;
    setDeleting(id);
    try {
      await deleteReview(id);
      setReviews(prev => prev.filter(r => r.id !== id));
      toast.success('Review record permanently removed from history.', 'Review Deleted');
    } catch (err) {
      const msg = extractErrorMessage(err);
      setError(msg);
      toast.error(msg, 'Delete Failed');
    } finally {
      setDeleting(null);
    }
  };

  const filtered = reviews.filter(r =>
    !search ||
    (r.filename ?? '').toLowerCase().includes(search.toLowerCase()) ||
    r.overall_status.toLowerCase().includes(search.toLowerCase()) ||
    r.risk_level.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ padding: '32px 44px', width: '100%', boxSizing: 'border-box', color: '#ffffff' }}>
      <div style={{ marginBottom: '28px', paddingBottom: '20px', borderBottom: '1px solid #1f1f23', width: '100%' }}>
        <h1 style={{ color: '#ffffff', fontSize: '24px', fontWeight: 700, margin: '0 0 6px 0', letterSpacing: '-0.02em' }}>
          Review History
        </h1>
        <p style={{ color: '#a1a1aa', fontSize: '13px', margin: 0 }}>
          Persistent review ledger stored in local SQLite database.
        </p>
      </div>

      {error && (
        <div style={{ marginBottom: '20px' }}>
          <ErrorBanner
            title="History Ledger Error"
            message={error}
            onDismiss={() => setError(null)}
            onRetry={load}
          />
        </div>
      )}

      <div style={{ position: 'relative', marginBottom: '20px', maxWidth: '420px' }}>
        <Search size={14} color="#71717a" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="filter by filename or status..."
          style={{
            width: '100%',
            padding: '10px 14px 10px 36px',
            background: '#0c0c0e',
            border: '1px solid #1f1f23',
            borderRadius: '6px',
            color: '#ffffff',
            fontSize: '13px',
            outline: 'none',
            fontFamily: 'inherit',
            boxSizing: 'border-box',
          }}
        />
      </div>

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '60px' }}>
          <LoadingSpinner size={28} />
        </div>
      ) : filtered.length === 0 ? (
        <div style={{
          background: '#0c0c0e',
          border: '1px dashed #1f1f23',
          borderRadius: '8px',
          padding: '48px',
          textAlign: 'center',
          color: '#71717a',
          fontSize: '13px',
          width: '100%',
          boxSizing: 'border-box',
        }}>
          {reviews.length === 0 ? 'No reviews stored yet.' : 'No reviews match filter.'}
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
                <th style={{ padding: '14px 18px' }}>TIMESTAMP</th>
                <th style={{ padding: '14px 18px', textAlign: 'right' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(r => (
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
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '14px 18px', textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '6px' }}>
                      <button
                        onClick={e => { e.stopPropagation(); navigate(`/review/${r.id}`); }}
                        style={{
                          background: '#18181b',
                          color: '#ffffff',
                          border: '1px solid #27272a',
                          borderRadius: '4px',
                          padding: '5px 12px',
                          fontSize: '11px',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          fontWeight: 500,
                        }}
                      >
                        <ExternalLink size={12} />
                        view
                      </button>
                      <button
                        onClick={e => handleDelete(r.id, e)}
                        disabled={deleting === r.id}
                        style={{
                          background: 'rgba(244, 63, 94, 0.1)',
                          color: '#fda4af',
                          border: '1px solid rgba(244, 63, 94, 0.25)',
                          borderRadius: '4px',
                          padding: '5px 12px',
                          fontSize: '11px',
                          cursor: deleting === r.id ? 'not-allowed' : 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          fontWeight: 500,
                        }}
                      >
                        <Trash2 size={12} />
                        delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ padding: '12px 18px', borderTop: '1px solid #1f1f23', color: '#71717a', fontSize: '11px', background: '#121215', fontFamily: 'JetBrains Mono, monospace' }}>
            {filtered.length} record{filtered.length !== 1 ? 's' : ''} {reviews.length !== filtered.length ? `(filtered from ${reviews.length})` : ''}
          </div>
        </div>
      )}
    </div>
  );
}
