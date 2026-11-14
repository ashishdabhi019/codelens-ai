import { useState } from 'react';
import { ShieldCheck, Cpu, HardDrive } from 'lucide-react';
import { useToast } from '../context/ToastContext';

export function Settings() {
  const toast = useToast();
  const [model, setModel] = useState('llama3.2');
  const [ollamaUrl, setOllamaUrl] = useState('http://localhost:11434');
  const [timeout, setTimeout_] = useState('120');
  const [maxSize, setMaxSize] = useState('500000');
  const [saved, setSaved] = useState(false);

  const inputStyle: React.CSSProperties = {
    background: '#121216',
    border: '1px solid #222228',
    borderRadius: '5px',
    color: '#ffffff',
    padding: '8px 13px',
    fontSize: '12.5px',
    outline: 'none',
    fontFamily: "'JetBrains Mono', monospace",
    width: '260px',
  };

  const handleSave = () => {
    setSaved(true);
    toast.success('Agent runtime preferences saved successfully.', 'Settings Saved');
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div style={{
      padding: '28px 40px 48px 40px',
      width: '100%',
      boxSizing: 'border-box',
      color: '#ffffff',
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    }}>
      <div style={{ marginBottom: '24px', paddingBottom: '16px', borderBottom: '1px solid #1a1a1e', width: '100%' }}>
        <h1 style={{ color: '#ffffff', fontSize: '22px', fontWeight: 600, margin: '0 0 4px 0', letterSpacing: '-0.025em' }}>
          Configuration & Environment
        </h1>
        <p style={{ color: '#8e8e93', fontSize: '13px', margin: 0, lineHeight: 1.5 }}>
          Agent runtime settings. Config file located at <code style={{ color: '#ffffff', background: '#16161a', padding: '2px 6px', borderRadius: '4px', border: '1px solid #23232a', fontFamily: "'JetBrains Mono', monospace", fontSize: '11.5px' }}>backend/.env</code>.
        </p>
      </div>

      <div style={{
        background: '#09090c',
        border: '1px solid #1c1c22',
        borderRadius: '7px',
        padding: '20px 24px',
        marginBottom: '18px',
        boxShadow: '0 4px 14px rgba(0, 0, 0, 0.4)',
        width: '100%',
        boxSizing: 'border-box',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
          <Cpu size={15} color="#ffffff" />
          <span style={{ color: '#ffffff', fontSize: '11.5px', fontWeight: 600, letterSpacing: '0.05em', fontFamily: "'JetBrains Mono', monospace" }}>
            LLM INFERENCE PROVIDER
          </span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0', borderBottom: '1px solid #16161b' }}>
          <div>
            <div style={{ color: '#ffffff', fontSize: '13px', fontWeight: 600 }}>Model Tag</div>
            <div style={{ color: '#71717a', fontSize: '12px' }}>Local Ollama model tag</div>
          </div>
          <input value={model} onChange={e => setModel(e.target.value)} style={inputStyle} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0' }}>
          <div>
            <div style={{ color: '#ffffff', fontSize: '13px', fontWeight: 600 }}>Endpoint URL</div>
            <div style={{ color: '#71717a', fontSize: '12px' }}>Ollama HTTP daemon address</div>
          </div>
          <input value={ollamaUrl} onChange={e => setOllamaUrl(e.target.value)} style={inputStyle} />
        </div>
      </div>

      <div style={{
        background: '#09090c',
        border: '1px solid #1c1c22',
        borderRadius: '7px',
        padding: '20px 24px',
        marginBottom: '18px',
        boxShadow: '0 4px 14px rgba(0, 0, 0, 0.4)',
        width: '100%',
        boxSizing: 'border-box',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
          <HardDrive size={15} color="#ffffff" />
          <span style={{ color: '#ffffff', fontSize: '11.5px', fontWeight: 600, letterSpacing: '0.05em', fontFamily: "'JetBrains Mono', monospace" }}>
            RESOURCE LIMITS & SAFETY
          </span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0', borderBottom: '1px solid #16161b' }}>
          <div>
            <div style={{ color: '#ffffff', fontSize: '13px', fontWeight: 600 }}>Max Input Size (bytes)</div>
            <div style={{ color: '#71717a', fontSize: '12px' }}>Rejects oversized diff payloads</div>
          </div>
          <input value={maxSize} onChange={e => setMaxSize(e.target.value)} style={{ ...inputStyle, width: '150px' }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0' }}>
          <div>
            <div style={{ color: '#ffffff', fontSize: '13px', fontWeight: 600 }}>Review Timeout (seconds)</div>
            <div style={{ color: '#71717a', fontSize: '12px' }}>Fails gracefully if LLM stalls</div>
          </div>
          <input value={timeout} onChange={e => setTimeout_(e.target.value)} style={{ ...inputStyle, width: '150px' }} />
        </div>
      </div>

      <div style={{
        background: '#09090c',
        border: '1px solid #1c1c22',
        borderRadius: '7px',
        padding: '20px 24px',
        marginBottom: '24px',
        boxShadow: '0 4px 14px rgba(0, 0, 0, 0.4)',
        width: '100%',
        boxSizing: 'border-box',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
          <ShieldCheck size={15} color="#ffffff" />
          <span style={{ color: '#ffffff', fontSize: '11.5px', fontWeight: 600, letterSpacing: '0.05em', fontFamily: "'JetBrains Mono', monospace" }}>
            SECURITY CONTROLS
          </span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '11px 0', fontSize: '13px', borderBottom: '1px solid #16161b' }}>
          <span style={{ color: '#a1a1aa' }}>Code Execution</span>
          <span style={{ color: '#4ade80', fontWeight: 600, fontFamily: "'JetBrains Mono', monospace", fontSize: '11.5px' }}>
            DISABLED (AST/diff inspection only)
          </span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '11px 0', fontSize: '13px', borderBottom: '1px solid #16161b' }}>
          <span style={{ color: '#a1a1aa' }}>Network Egress</span>
          <span style={{ color: '#4ade80', fontWeight: 600, fontFamily: "'JetBrains Mono', monospace", fontSize: '11.5px' }}>
            LOCAL ONLY (no cloud transmission)
          </span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '11px 0', fontSize: '13px' }}>
          <span style={{ color: '#a1a1aa' }}>Storage</span>
          <span style={{ color: '#ffffff', fontWeight: 600, fontFamily: "'JetBrains Mono', monospace", fontSize: '11.5px' }}>
            SQLite (codelens.db)
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', width: '100%', paddingBottom: '32px' }}>
        <button
          onClick={handleSave}
          style={{
            background: saved ? '#16a34a' : '#ffffff',
            color: saved ? '#ffffff' : '#000000',
            border: 'none',
            borderRadius: '6px',
            padding: '11px 22px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
            boxShadow: '0 2px 6px rgba(255, 255, 255, 0.1)',
            transition: 'all 0.12s ease',
          }}
          onMouseEnter={e => { if (!saved) e.currentTarget.style.background = '#e4e4e7'; }}
          onMouseLeave={e => { if (!saved) e.currentTarget.style.background = '#ffffff'; }}
        >
          {saved ? 'Saved Preferences' : 'Save Preferences'}
        </button>
      </div>
    </div>
  );
}
