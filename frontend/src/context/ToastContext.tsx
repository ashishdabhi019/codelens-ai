import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { Check, AlertCircle, AlertTriangle, Info, X } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface ToastItem {
  id: string;
  type: ToastType;
  title?: string;
  message: string;
  duration?: number;
}

interface ToastContextValue {
  showToast: (toast: Omit<ToastItem, 'id'>) => void;
  success: (message: string, title?: string) => void;
  error: (message: string, title?: string) => void;
  warning: (message: string, title?: string) => void;
  info: (message: string, title?: string) => void;
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const showToast = useCallback((toast: Omit<ToastItem, 'id'>) => {
    const id = Math.random().toString(36).substring(2, 9);
    const item: ToastItem = { ...toast, id };
    // Cap visible toasts to at most 3 to prevent notification spam
    setToasts(prev => [...prev.slice(-2), item]);

    const duration = toast.duration ?? (toast.type === 'error' ? 5000 : 3200);
    if (duration > 0) {
      setTimeout(() => {
        dismiss(id);
      }, duration);
    }
  }, [dismiss]);

  const success = useCallback((message: string, title?: string) => {
    showToast({ type: 'success', message, title });
  }, [showToast]);

  const error = useCallback((message: string, title?: string) => {
    showToast({ type: 'error', message, title });
  }, [showToast]);

  const warning = useCallback((message: string, title?: string) => {
    showToast({ type: 'warning', message, title });
  }, [showToast]);

  const info = useCallback((message: string, title?: string) => {
    showToast({ type: 'info', message, title });
  }, [showToast]);

  const contextValue = useMemo(
    () => ({ showToast, success, error, warning, info, dismiss }),
    [showToast, success, error, warning, info, dismiss]
  );

  return (
    <ToastContext.Provider value={contextValue}>
      {children}

      {/* BOTTOM-RIGHT Modern Glassmorphic Pill Stack */}
      <div
        style={{
          position: 'fixed',
          bottom: '24px',
          right: '28px',
          zIndex: 99999,
          display: 'flex',
          flexDirection: 'column-reverse',
          alignItems: 'flex-end',
          gap: '8px',
          maxWidth: '420px',
          pointerEvents: 'none',
        }}
        aria-live="polite"
      >
        {toasts.map(t => {
          const isSuccess = t.type === 'success';
          const isError = t.type === 'error';
          const isWarning = t.type === 'warning';

          const accentColor = isSuccess ? '#4ade80' : isError ? '#f43f5e' : isWarning ? '#f59e0b' : '#38bdf8';
          const badgeBg = isSuccess
            ? 'rgba(74, 222, 128, 0.12)'
            : isError
            ? 'rgba(244, 63, 94, 0.12)'
            : isWarning
            ? 'rgba(245, 158, 11, 0.12)'
            : 'rgba(56, 189, 248, 0.12)';
          const badgeBorder = isSuccess
            ? 'rgba(74, 222, 128, 0.25)'
            : isError
            ? 'rgba(244, 63, 94, 0.25)'
            : isWarning
            ? 'rgba(245, 158, 11, 0.25)'
            : 'rgba(56, 189, 248, 0.25)';

          const Icon = isSuccess ? Check : isError ? AlertCircle : isWarning ? AlertTriangle : Info;

          return (
            <div
              key={t.id}
              style={{
                pointerEvents: 'auto',
                background: 'rgba(15, 15, 19, 0.94)',
                backdropFilter: 'blur(16px)',
                WebkitBackdropFilter: 'blur(16px)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '10px',
                padding: '9px 12px 9px 10px',
                boxShadow: '0 16px 36px -8px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(255, 255, 255, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.07)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '10px',
                color: '#ffffff',
                fontFamily: "'Inter', sans-serif",
                animation: 'toastSlideUp 0.22s cubic-bezier(0.16, 1, 0.3, 1)',
                width: 'auto',
                maxWidth: '380px',
              }}
            >
              {/* Tactile micro-badge for status icon */}
              <div
                style={{
                  width: '20px',
                  height: '20px',
                  borderRadius: '5px',
                  background: badgeBg,
                  border: `1px solid ${badgeBorder}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                <Icon size={12} color={accentColor} strokeWidth={2.6} />
              </div>

              {/* Text Content */}
              <div style={{ flex: 1, minWidth: 0 }}>
                {t.title ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1px' }}>
                    <div
                      style={{
                        fontSize: '12.5px',
                        fontWeight: 600,
                        color: '#ffffff',
                        letterSpacing: '-0.01em',
                        lineHeight: 1.3,
                      }}
                    >
                      {t.title}
                    </div>
                    {t.message && (
                      <div
                        style={{
                          fontSize: '11.5px',
                          color: '#94949e',
                          lineHeight: 1.35,
                          wordBreak: 'break-word',
                        }}
                      >
                        {t.message}
                      </div>
                    )}
                  </div>
                ) : (
                  <div
                    style={{
                      fontSize: '12px',
                      fontWeight: 500,
                      color: '#f4f4f5',
                      lineHeight: 1.35,
                      wordBreak: 'break-word',
                    }}
                  >
                    {t.message}
                  </div>
                )}
              </div>

              {/* Minimalist Close Button */}
              <button
                type="button"
                onClick={() => dismiss(t.id)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  color: '#71717a',
                  width: '20px',
                  height: '20px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  borderRadius: '5px',
                  transition: 'all 0.12s ease',
                  flexShrink: 0,
                  padding: 0,
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.color = '#ffffff';
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.color = '#71717a';
                  e.currentTarget.style.background = 'transparent';
                }}
                aria-label="Close notification"
              >
                <X size={11} strokeWidth={2.2} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}
