import { AlertTriangle, X, RefreshCw } from 'lucide-react';

interface ErrorBannerProps {
  title?: string;
  message: string;
  onDismiss?: () => void;
  onRetry?: () => void;
}

export function ErrorBanner({ title, message, onDismiss, onRetry }: ErrorBannerProps) {
  return (
    <div style={{
      background: 'rgba(244, 63, 94, 0.08)',
      border: '1px solid rgba(244, 63, 94, 0.28)',
      borderRadius: '7px',
      padding: '12px 16px',
      display: 'flex',
      alignItems: 'flex-start',
      gap: '12px',
      color: '#ffffff',
      fontSize: '12.5px',
      fontFamily: "'Inter', sans-serif",
      boxShadow: '0 2px 10px rgba(244, 63, 94, 0.08)',
    }}>
      <div style={{
        width: '24px',
        height: '24px',
        borderRadius: '5px',
        background: 'rgba(244, 63, 94, 0.16)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexShrink: 0,
        marginTop: '1px',
      }}>
        <AlertTriangle size={14} color="#f43f5e" />
      </div>

      <div style={{ flex: 1, minWidth: 0 }}>
        {title && (
          <div style={{
            fontWeight: 600,
            fontSize: '13px',
            color: '#f43f5e',
            marginBottom: '3px',
            letterSpacing: '-0.01em',
          }}>
            {title}
          </div>
        )}
        <div style={{ color: '#fda4af', lineHeight: 1.5, wordBreak: 'break-word' }}>
          {message}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
        {onRetry && (
          <button
            onClick={onRetry}
            style={{
              background: 'rgba(244, 63, 94, 0.14)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              borderRadius: '4px',
              color: '#fda4af',
              padding: '4px 8px',
              fontSize: '11px',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
              transition: 'all 0.12s ease',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(244, 63, 94, 0.25)'}
            onMouseLeave={e => e.currentTarget.style.background = 'rgba(244, 63, 94, 0.14)'}
          >
            <RefreshCw size={11} />
            <span>Retry</span>
          </button>
        )}

        {onDismiss && (
          <button
            onClick={onDismiss}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: '#fda4af',
              padding: '4px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '4px',
              opacity: 0.8,
              transition: 'opacity 0.12s ease',
            }}
            onMouseEnter={e => e.currentTarget.style.opacity = '1'}
            onMouseLeave={e => e.currentTarget.style.opacity = '0.8'}
            aria-label="Dismiss error"
          >
            <X size={14} />
          </button>
        )}
      </div>
    </div>
  );
}
