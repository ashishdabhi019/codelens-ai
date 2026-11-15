import { useState, useRef, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { submitReview, extractErrorMessage } from '../services/api';
import type { ReviewRequest } from '../types';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorBanner } from '../components/ErrorBanner';
import { useToast } from '../context/ToastContext';
import {
  Play,
  Upload,
  FileCode2,
  RotateCcw,
  Layers,
  Bug,
  ShieldAlert,
  Zap,
  CheckCircle2,
  Sparkles,
  ArrowRight,
  Check,
  ChevronDown,
} from 'lucide-react';

const FOCUS_OPTIONS: {
  value: ReviewRequest['focus'];
  label: string;
  icon: React.ComponentType<{ size?: number; color?: string }>;
}[] = [
  { value: 'all', label: 'All Categories', icon: Layers },
  { value: 'bugs', label: 'Bugs & Logic', icon: Bug },
  { value: 'security', label: 'Security Risks', icon: ShieldAlert },
  { value: 'performance', label: 'Performance', icon: Zap },
  { value: 'testing', label: 'Missing Tests', icon: CheckCircle2 },
  { value: 'style', label: 'Code Quality', icon: Sparkles },
];

const LANGUAGES = [
  '', 'Python', 'TypeScript', 'JavaScript', 'Go', 'Rust', 'Java', 'C++', 'C', 'Ruby', 'PHP',
];

interface SampleScenario {
  key: string;
  title: string;
  tagline: string;
  focus: ReviewRequest['focus'];
  language: string;
  filename: string;
  badge: string;
  badgeColor: string;
  badgeBg: string;
  icon: React.ComponentType<{ size?: number; color?: string }>;
  content: string;
}

const SAMPLE_SCENARIOS: SampleScenario[] = [
  {
    key: 'security',
    title: 'SQL Injection & RCE',
    tagline: 'Raw f-string query in UserService + hardcoded credentials & eval()',
    focus: 'security',
    language: 'Python',
    filename: 'user_service.py',
    badge: 'Critical Vulnerability',
    badgeColor: '#f43f5e',
    badgeBg: 'rgba(244, 63, 94, 0.12)',
    icon: ShieldAlert,
    content: `import sqlite3
+import os
+
+DB_PASSWORD = "admin1234secret"

class UserService:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)

    def get_user_by_username(self, username: str):
+        cursor = self.conn.cursor()
+        cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
+        return cursor.fetchone()

    def eval_filter(self, filter_expr: str):
+        return eval(filter_expr)`,
  },
  {
    key: 'bug',
    title: 'Calculation Logic Bug',
    tagline: 'Inverted discount rate formula, unchecked division, tier assumptions & negative bounds',
    focus: 'bugs',
    language: 'Python',
    filename: 'calculator.py',
    badge: 'Logic Bug',
    badgeColor: '#f59e0b',
    badgeBg: 'rgba(245, 158, 11, 0.12)',
    icon: Bug,
    content: `def calculate_discount(price, discount_percent):
    # Inverted discount formula
    discounted = price / (1 - discount_percent / 100)
    return discounted

def calculate_average(values):
    # Empty collection crash
    total = sum(values)
    return total / len(values)

def get_tier_discount(user_type):
    # Tier discount discrepancy without business specification
    if user_type == "premium":
        return 0.05
    return 0.0

def calculate_shipping(weight, rate_per_kg):
    # Missing negative value validation
    if weight == 0:
        return 0.0
    # Negative weight or rate leads to invalid negative cost
    return weight * rate_per_kg`,
  },
  {
    key: 'tests',
    title: 'Missing Boundary Tests',
    tagline: 'New calculate_median() lacks empty array & even length test coverage',
    focus: 'testing',
    language: 'Python',
    filename: 'math_utils.py',
    badge: 'Test Coverage',
    badgeColor: '#38bdf8',
    badgeBg: 'rgba(56, 189, 248, 0.12)',
    icon: CheckCircle2,
    content: `def calculate_median(values):
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    mid = len(sorted_vals) // 2
    if len(sorted_vals) % 2 == 0:
        return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2
    return sorted_vals[mid]`,
  },
];

function highlightTokens(text: string, defaultColor: string = '#d4d4d4'): React.ReactNode {
  const TOKEN_REGEX = /(#.*$)|([fbrFBR]?"""[\s\S]*?"""|[fbrFBR]?'''[\s\S]*?'''|[fbrFBR]?"(?:[^"\\]|\\.)*"|[fbrFBR]?'(?:[^'\\]|\\.)*')|(\b[a-zA-Z_][a-zA-Z0-9_]*(?=\s*\())|(\b(?:return|if|else|elif|for|while|try|except|finally|raise|yield|break|continue|pass|assert)\b)|(\b(?:def|class|import|from|as|with|lambda|global|nonlocal|async|await|in|is|not|and|or)\b)|(\b(?:int|str|float|bool|list|dict|set|tuple|bytes|object|type|Exception|ValueError|TypeError|KeyError|IndexError|RuntimeError)\b)|(\b(?:True|False|None)\b)|(\b[A-Z][a-zA-Z0-9_]+\b)|(\bself\b)|(\b\d+(?:\.\d+)?\b)/g;

  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = TOKEN_REGEX.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(
        <span key={`txt-${lastIndex}`} style={{ color: defaultColor }}>
          {text.substring(lastIndex, match.index)}
        </span>
      );
    }

    if (match[1]) {
      // 1: Comment -> VS Code green italic #6A9955
      parts.push(
        <span key={`com-${match.index}`} style={{ color: '#6a9955', fontStyle: 'italic' }}>
          {match[1]}
        </span>
      );
    } else if (match[2]) {
      // 2: String -> VS Code warm amber #CE9178
      parts.push(
        <span key={`str-${match.index}`} style={{ color: '#ce9178' }}>
          {match[2]}
        </span>
      );
    } else if (match[3]) {
      // 3: Function / Method declaration or call -> VS Code yellow #DCDCAA
      parts.push(
        <span key={`fn-${match.index}`} style={{ color: '#dcdcaa' }}>
          {match[3]}
        </span>
      );
    } else if (match[4]) {
      // 4: Control flow -> VS Code control purple #C586C0
      parts.push(
        <span key={`ctrl-${match.index}`} style={{ color: '#c586c0', fontWeight: 600 }}>
          {match[4]}
        </span>
      );
    } else if (match[5]) {
      // 5: Definition / Keyword -> VS Code blue #569CD6
      parts.push(
        <span key={`kw-${match.index}`} style={{ color: '#569cd6', fontWeight: 600 }}>
          {match[5]}
        </span>
      );
    } else if (match[6]) {
      // 6: Builtin Types -> VS Code teal #4EC9B0
      parts.push(
        <span key={`typ-${match.index}`} style={{ color: '#4ec9b0' }}>
          {match[6]}
        </span>
      );
    } else if (match[7]) {
      // 7: Literals (True, False, None) -> VS Code blue #569CD6
      parts.push(
        <span key={`lit-${match.index}`} style={{ color: '#569cd6' }}>
          {match[7]}
        </span>
      );
    } else if (match[8]) {
      // 8: Classes (PascalCase) -> VS Code teal #4EC9B0
      parts.push(
        <span key={`cls-${match.index}`} style={{ color: '#4ec9b0', fontWeight: 600 }}>
          {match[8]}
        </span>
      );
    } else if (match[9]) {
      // 9: self -> VS Code light blue #9CDCFE
      parts.push(
        <span key={`slf-${match.index}`} style={{ color: '#9cdcfe', fontStyle: 'italic' }}>
          {match[9]}
        </span>
      );
    } else if (match[10]) {
      // 10: Numbers -> VS Code mint green #B5CEA8
      parts.push(
        <span key={`num-${match.index}`} style={{ color: '#b5cea8' }}>
          {match[10]}
        </span>
      );
    }

    lastIndex = TOKEN_REGEX.lastIndex;
  }

  if (lastIndex < text.length) {
    parts.push(
      <span key={`end-${lastIndex}`} style={{ color: defaultColor }}>
        {text.substring(lastIndex)}
      </span>
    );
  }

  return parts.length > 0 ? parts : <span style={{ color: defaultColor }}>{text}</span>;
}

function renderDiffSyntaxLine(line: string, idx: number) {
  const isAdd = line.startsWith('+') && !line.startsWith('+++');
  const isDel = line.startsWith('-') && !line.startsWith('---');
  const isHunk = line.startsWith('@@');
  const isHeader = line.startsWith('diff --git') || line.startsWith('index ') || line.startsWith('---') || line.startsWith('+++');

  let bg = 'transparent';
  let lineContent: React.ReactNode = line;

  if (isAdd) {
    bg = 'rgba(74, 222, 128, 0.08)';
    lineContent = (
      <>
        <span style={{ color: '#4ade80', fontWeight: 700, marginRight: '1px' }}>+</span>
        {highlightTokens(line.slice(1), '#9cdcfe')}
      </>
    );
  } else if (isDel) {
    bg = 'rgba(244, 63, 94, 0.08)';
    lineContent = (
      <>
        <span style={{ color: '#f87171', fontWeight: 700, marginRight: '1px' }}>-</span>
        {highlightTokens(line.slice(1), '#f87171')}
      </>
    );
  } else if (isHunk) {
    bg = 'rgba(56, 189, 248, 0.07)';
    lineContent = <span style={{ color: '#38bdf8' }}>{line}</span>;
  } else if (isHeader) {
    lineContent = <span style={{ color: '#858585' }}>{line}</span>;
  } else {
    lineContent = highlightTokens(line, '#d4d4d4');
  }

  return (
    <div
      key={idx}
      style={{
        height: '22px',
        lineHeight: '22px',
        background: bg,
        whiteSpace: 'pre',
      }}
    >
      {lineContent || '\u00A0'}
    </div>
  );
}

export function NewReview() {
  const [diffContent, setDiffContent] = useState('');
  const [focus, setFocus] = useState<ReviewRequest['focus']>('all');
  const [language, setLanguage] = useState('');
  const [instructions, setInstructions] = useState('');
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [activeSample, setActiveSample] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [promptFocused, setPromptFocused] = useState(false);
  const [showShortcutTooltip, setShowShortcutTooltip] = useState(false);
  const [focusMenuOpen, setFocusMenuOpen] = useState(false);
  const [langMenuOpen, setLangMenuOpen] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const highlightRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const promptTextareaRef = useRef<HTMLTextAreaElement>(null);
  const focusMenuRef = useRef<HTMLDivElement>(null);
  const langMenuRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const toast = useToast();

  // Close custom dropdowns on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (focusMenuRef.current && !focusMenuRef.current.contains(e.target as Node)) {
        setFocusMenuOpen(false);
      }
      if (langMenuRef.current && !langMenuRef.current.contains(e.target as Node)) {
        setLangMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Compute line stats
  const lines = diffContent ? diffContent.split('\n') : [''];
  const totalLines = diffContent ? lines.length : 0;
  const hasDiffMarkers = lines.some(l => (l.startsWith('+') && !l.startsWith('+++')) || (l.startsWith('-') && !l.startsWith('---')));
  const isDiffFormat = (diffContent.includes('--- ') && diffContent.includes('+++ ')) || hasDiffMarkers;
  const addedCount = lines.filter(l => l.startsWith('+') && !l.startsWith('+++')).length;
  const removedCount = lines.filter(l => l.startsWith('-') && !l.startsWith('---')).length;

  const handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => {
    const { scrollTop, scrollLeft } = e.currentTarget;
    if (gutterRef.current) {
      gutterRef.current.scrollTop = scrollTop;
    }
    if (highlightRef.current) {
      highlightRef.current.scrollTop = scrollTop;
      highlightRef.current.scrollLeft = scrollLeft;
    }
  };

  const handleEditorKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const target = e.currentTarget;
      const start = target.selectionStart;
      const end = target.selectionEnd;
      const value = target.value;
      const newValue = value.substring(0, start) + '    ' + value.substring(end);
      setDiffContent(newValue);
      requestAnimationFrame(() => {
        target.selectionStart = target.selectionEnd = start + 4;
      });
    }
  };

  const detectLanguageFromFilename = (filename: string): string => {
    const ext = filename.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'py': return 'Python';
      case 'ts':
      case 'tsx': return 'TypeScript';
      case 'js':
      case 'jsx': return 'JavaScript';
      case 'go': return 'Go';
      case 'rs': return 'Rust';
      case 'java': return 'Java';
      case 'cpp':
      case 'cc':
      case 'cxx':
      case 'h':
      case 'hpp': return 'C++';
      case 'c': return 'C';
      case 'rb': return 'Ruby';
      case 'php': return 'PHP';
      default: return '';
    }
  };

  const convertSourceToDiff = (filename: string, code: string): string => {
    // If the input is already a raw unified diff, send it directly
    if (code.includes('--- ') && code.includes('+++ ') && code.includes('@@')) {
      return code;
    }
    // Otherwise, synthesize a unified diff wrapper behind the scenes so users can paste
    // pure code directly into Line 1 without manually authoring raw git diff plumbing headers
    const cleanLines = code.split('\n');
    const hasDiff = cleanLines.some(l => (l.startsWith('+') && !l.startsWith('+++')) || (l.startsWith('-') && !l.startsWith('---')));
    const header = [
      `diff --git a/${filename} b/${filename}`,
      `--- a/${filename}`,
      `+++ b/${filename}`,
      `@@ -1,${Math.max(1, cleanLines.length)} +1,${Math.max(1, cleanLines.length)} @@`,
    ];
    const diffLines = cleanLines.map(line => {
      if (hasDiff) {
        return line.startsWith('+') || line.startsWith('-') ? line : ` ${line}`;
      }
      return `+${line}`;
    });
    return header.concat(diffLines).join('\n');
  };

  const handleFile = useCallback((file: File) => {
    if (file.size > 500 * 1024) {
      toast.error('File size exceeds the 500KB security limit.', 'File Too Large');
      return;
    }

    setUploadedFile(file);
    setActiveSample(null);
    const reader = new FileReader();
    reader.onload = e => {
      const text = e.target?.result;
      if (typeof text === 'string') {
        const detectedLang = detectLanguageFromFilename(file.name);
        if (detectedLang) {
          setLanguage(detectedLang);
        }
        // Load the clean, pure code directly into the editor without synthetic diff headers
        setDiffContent(text);
        toast.info(`Loaded ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
      }
    };
    reader.onerror = () => {
      toast.error('Failed to read the selected file.', 'File Read Error');
    };
    reader.readAsText(file);
  }, [toast]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const loadScenario = (scenario: SampleScenario) => {
    setDiffContent(scenario.content);
    setFocus(scenario.focus);
    setLanguage(scenario.language);
    setActiveSample(scenario.key);
    setUploadedFile(null);
    setError(null);
    toast.info(`Loaded scenario: ${scenario.title}`);
  };

  const handleClear = () => {
    if (diffContent || uploadedFile) {
      toast.info('Cleared editor contents');
    }
    setDiffContent('');
    setUploadedFile(null);
    setActiveSample(null);
    setError(null);
  };

  const handleSubmit = async () => {
    if (!diffContent.trim() && !uploadedFile) {
      const msg = 'Please provide code changes or upload a file.';
      setError(msg);
      toast.warning(msg, 'Input Required');
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const activeScen = SAMPLE_SCENARIOS.find(s => s.key === activeSample);
      const filename = uploadedFile?.name || activeScen?.filename || (language ? `file.${language.toLowerCase()}` : 'code.py');
      // If the content in editor is pure code (not already a unified diff), wrap it behind the scenes for the AI reviewer
      const payloadContent = convertSourceToDiff(filename, diffContent);

      const response = await submitReview({
        diff_content: payloadContent,
        focus,
        language: language || undefined,
        additional_instructions: instructions || undefined,
        filename,
      });
      toast.success('Code analysis completed successfully');
      navigate(`/review/${response.id}`);
    } catch (err: unknown) {
      const msg = extractErrorMessage(err);
      setError(msg);
      toast.error(msg, 'Review Failed');
    } finally {
      setLoading(false);
    }
  };

  // Keyboard shortcut: Cmd/Ctrl + Enter to submit
  useEffect(() => {
    const onGlobalKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault();
        handleSubmit();
      }
    };
    window.addEventListener('keydown', onGlobalKey);
    return () => window.removeEventListener('keydown', onGlobalKey);
  }, [diffContent, uploadedFile, focus, language, instructions]);

  const activeScenarioObj = SAMPLE_SCENARIOS.find(s => s.key === activeSample);

  return (
    <div style={{
      padding: '28px 40px 48px 40px',
      width: '100%',
      boxSizing: 'border-box',
      color: '#ffffff',
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    }}>
      {/* Top Header */}
      <div style={{ marginBottom: '22px', paddingBottom: '16px', borderBottom: '1px solid #1a1a1e', width: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <h1 style={{
              color: '#ffffff',
              fontSize: '22px',
              fontWeight: 600,
              margin: '0 0 4px 0',
              letterSpacing: '-0.025em',
            }}>
              New Code Review
            </h1>
            <p style={{
              color: '#8e8e93',
              fontSize: '13px',
              margin: 0,
              lineHeight: 1.5,
              fontWeight: 400,
            }}>
              Inspect Git unified diffs with deterministic rule scanning and LLM orchestration.
            </p>
          </div>
          <div style={{
            fontSize: '11px',
            color: '#71717a',
            fontFamily: "'JetBrains Mono', monospace",
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}>
            <span>Submit shortcut:</span>
            <kbd style={{
              background: '#141417',
              border: '1px solid #27272a',
              padding: '2px 6px',
              borderRadius: '4px',
              color: '#e4e4e7',
              fontSize: '10.5px',
              fontWeight: 500,
            }}>⌘ / Ctrl</kbd>
            <span style={{ color: '#52525b' }}>+</span>
            <kbd style={{
              background: '#141417',
              border: '1px solid #27272a',
              padding: '2px 6px',
              borderRadius: '4px',
              color: '#e4e4e7',
              fontSize: '10.5px',
              fontWeight: 500,
            }}>Enter</kbd>
          </div>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: '18px' }}>
          <ErrorBanner
            title="Review Error"
            message={error}
            onDismiss={() => setError(null)}
            onRetry={handleSubmit}
          />
        </div>
      )}

      {/* REIMAGINED: Pre-test Sample Scenarios Bar */}
      <div style={{ marginBottom: '22px' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '10px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Sparkles size={13} color="#a1a1aa" />
            <span style={{
              fontSize: '11px',
              fontWeight: 600,
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
              color: '#71717a',
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              Quick-Load Evaluation Test Cases
            </span>
          </div>
          {activeSample && (
            <button
              onClick={handleClear}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#8e8e93',
                fontSize: '11px',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                fontFamily: "'JetBrains Mono', monospace",
                transition: 'color 0.12s ease',
              }}
              onMouseEnter={e => e.currentTarget.style.color = '#ffffff'}
              onMouseLeave={e => e.currentTarget.style.color = '#8e8e93'}
            >
              <RotateCcw size={11} />
              <span>Reset to blank</span>
            </button>
          )}
        </div>

        {/* 3 Interactive Scenario Cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
          gap: '12px',
        }}>
          {SAMPLE_SCENARIOS.map(scen => {
            const isSelected = activeSample === scen.key;
            const Icon = scen.icon;
            return (
              <button
                key={scen.key}
                onClick={() => loadScenario(scen)}
                style={{
                  textAlign: 'left',
                  background: isSelected ? '#121216' : '#0a0a0d',
                  border: isSelected ? '1px solid #ffffff' : '1px solid #1a1a1f',
                  borderRadius: '7px',
                  padding: '12px 14px',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  transition: 'all 0.15s ease',
                  position: 'relative',
                  outline: 'none',
                  boxShadow: isSelected ? '0 0 0 1px #ffffff, 0 4px 14px rgba(0,0,0,0.4)' : 'none',
                }}
                onMouseEnter={e => {
                  if (!isSelected) {
                    e.currentTarget.style.borderColor = '#2e2e38';
                    e.currentTarget.style.background = '#0e0e12';
                  }
                }}
                onMouseLeave={e => {
                  if (!isSelected) {
                    e.currentTarget.style.borderColor = '#1a1a1f';
                    e.currentTarget.style.background = '#0a0a0d';
                  }
                }}
              >
                {/* Card Top: Title + Status Pill */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', width: '100%' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                    <div style={{
                      width: '20px',
                      height: '20px',
                      borderRadius: '4px',
                      background: isSelected ? '#ffffff' : '#18181d',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}>
                      <Icon size={12} color={isSelected ? '#000000' : '#d4d4d8'} />
                    </div>
                    <span style={{
                      fontSize: '12.5px',
                      fontWeight: 600,
                      color: isSelected ? '#ffffff' : '#e4e4e7',
                      letterSpacing: '-0.015em',
                      fontFamily: "'Inter', sans-serif",
                    }}>
                      {scen.title}
                    </span>
                  </div>

                  {isSelected ? (
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 600,
                      color: '#000000',
                      background: '#ffffff',
                      padding: '1px 6px',
                      borderRadius: '3px',
                      fontFamily: "'JetBrains Mono', monospace",
                      display: 'flex',
                      alignItems: 'center',
                      gap: '3px',
                    }}>
                      <Check size={9} strokeWidth={3} /> ACTIVE
                    </span>
                  ) : (
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 500,
                      color: scen.badgeColor,
                      background: scen.badgeBg,
                      border: `1px solid ${scen.badgeColor}22`,
                      padding: '1px 6px',
                      borderRadius: '3px',
                      fontFamily: "'JetBrains Mono', monospace",
                    }}>
                      {scen.badge}
                    </span>
                  )}
                </div>

                {/* Card Subtitle */}
                <p style={{
                  margin: '2px 0 0 0',
                  fontSize: '11.5px',
                  color: isSelected ? '#a1a1aa' : '#71717a',
                  lineHeight: 1.4,
                  fontWeight: 400,
                  fontFamily: "'Inter', sans-serif",
                }}>
                  {scen.tagline}
                </p>

                {/* Card Meta Footer */}
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginTop: '4px',
                  paddingTop: '6px',
                  borderTop: isSelected ? '1px solid #22222a' : '1px solid #141418',
                  fontSize: '10.5px',
                  color: '#71717a',
                  fontFamily: "'JetBrains Mono', monospace",
                }}>
                  <span>target: <span style={{ color: isSelected ? '#ffffff' : '#a1a1aa' }}>{scen.filename}</span></span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', color: isSelected ? '#ffffff' : '#71717a' }}>
                    {isSelected ? 'Loaded in studio' : 'Click to load'} <ArrowRight size={10} />
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Code Studio & AI Prompt Bar */}
      <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '14px' }}>
        
        {/* Code Editor Window */}
        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          style={{
            position: 'relative',
            background: '#09090c',
            border: `1px solid ${dragOver ? '#ffffff' : '#1c1c22'}`,
            borderRadius: '7px',
            overflow: 'hidden',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.45)',
            transition: 'border-color 0.15s ease',
            minWidth: 0,
          }}
        >
          {/* Editor Top Toolbar: Uncluttered & Focused */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: '#0f0f13',
            borderBottom: '1px solid #1c1c22',
            padding: '8px 14px',
            flexWrap: 'wrap',
            gap: '10px',
          }}>
            {/* File Tab + Diff Stats */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                background: diffContent || uploadedFile ? '#16161b' : '#111114',
                border: diffContent || uploadedFile ? '1px solid #23232a' : '1px solid #1a1a20',
                padding: '4px 9px',
                borderRadius: '4px',
                fontSize: '11.5px',
                color: diffContent || uploadedFile ? '#ffffff' : '#63636e',
                fontFamily: "'JetBrains Mono', monospace",
                fontWeight: 500,
              }}>
                <FileCode2 size={13} color={diffContent || uploadedFile ? '#a1a1aa' : '#45454e'} />
                <span>
                  {uploadedFile
                    ? uploadedFile.name
                    : activeScenarioObj
                    ? activeScenarioObj.filename
                    : diffContent
                    ? 'patch.diff'
                    : 'no diff loaded'}
                </span>
              </div>

              {diffContent && (
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  fontSize: '11px',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontWeight: 500,
                }}>
                  {isDiffFormat && (
                    <>
                      <span style={{ color: '#4ade80' }}>+{addedCount}</span>
                      <span style={{ color: '#f43f5e' }}>-{removedCount}</span>
                    </>
                  )}
                  <span style={{ color: '#71717a' }}>{totalLines} lines</span>
                </div>
              )}
            </div>

            {/* Right Tools: Upload & Clear */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <button
                onClick={() => fileInputRef.current?.click()}
                title="Upload code or diff file (.py, .ts, .js, .go, .rs, .java, .diff, .patch, etc.)"
                style={{
                  background: '#16161b',
                  color: '#f4f4f5',
                  border: '1px solid #26262e',
                  borderRadius: '4px',
                  padding: '4px 10px',
                  fontSize: '11px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  fontWeight: 500,
                  fontFamily: "'Inter', sans-serif",
                  transition: 'all 0.12s ease',
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.background = '#22222a';
                  e.currentTarget.style.borderColor = '#383844';
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.background = '#16161b';
                  e.currentTarget.style.borderColor = '#26262e';
                }}
              >
                <Upload size={12} />
                <span>Upload File</span>
              </button>

              {diffContent && (
                <button
                  onClick={handleClear}
                  title="Clear editor contents"
                  style={{
                    background: 'transparent',
                    color: '#71717a',
                    border: '1px solid #222228',
                    borderRadius: '4px',
                    padding: '4px 8px',
                    fontSize: '11px',
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontWeight: 500,
                    fontFamily: "'Inter', sans-serif",
                    transition: 'all 0.12s ease',
                  }}
                  onMouseEnter={e => {
                    e.currentTarget.style.color = '#f43f5e';
                    e.currentTarget.style.borderColor = 'rgba(244, 63, 94, 0.3)';
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.color = '#71717a';
                    e.currentTarget.style.borderColor = '#222228';
                  }}
                >
                  <RotateCcw size={11} />
                  <span>Clear</span>
                </button>
              )}
            </div>
          </div>

          {/* Hidden File Input supporting all code and diff formats */}
          <input
            ref={fileInputRef}
            type="file"
            accept=".diff,.patch,.py,.js,.ts,.tsx,.jsx,.go,.rs,.java,.cpp,.c,.h,.hpp,.cs,.rb,.php,.swift,.kt,.sql,.sh,.txt,text/*"
            style={{ display: 'none' }}
            onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
          />

          {/* Drag Overlay Hint */}
          {dragOver && (
            <div style={{
              position: 'absolute',
              inset: 0,
              background: 'rgba(9, 9, 12, 0.94)',
              zIndex: 10,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '10px',
              border: '2px dashed #ffffff',
              borderRadius: '7px',
              color: '#ffffff',
            }}>
              <Upload size={28} />
              <div style={{ fontSize: '13.5px', fontWeight: 600 }}>Drop .diff or .patch file to load into studio</div>
            </div>
          )}

          {/* Editor Body: Line Number Gutter + Textarea */}
          <div style={{ display: 'flex', minHeight: '500px', background: '#070709', position: 'relative' }}>
            {/* Gutter */}
            <div
              ref={gutterRef}
              style={{
                width: '48px',
                padding: '14px 10px 14px 0',
                textAlign: 'right',
                userSelect: 'none',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '12px',
                lineHeight: '22px',
                fontVariantNumeric: 'tabular-nums',
                background: '#09090c',
                borderRight: '1px solid #1a1a20',
                overflowY: 'hidden',
                flexShrink: 0,
                zIndex: 3,
              }}
            >
              {lines.map((line, idx) => {
                const isAdd = line.startsWith('+') && !line.startsWith('+++');
                const isDel = line.startsWith('-') && !line.startsWith('---');
                const isHunk = line.startsWith('@@');
                const color = isAdd ? '#4ade80' : isDel ? '#f43f5e' : isHunk ? '#38bdf8' : '#52525b';
                const opacity = diffContent ? (line ? 1 : 0.4) : 0.2;
                return (
                  <div key={idx} style={{ height: '22px', color, opacity }}>
                    {idx + 1}
                  </div>
                );
              })}
            </div>

            {/* Code Studio Stage */}
            <div style={{ position: 'relative', flex: 1, minHeight: '500px', overflow: 'hidden' }}>
              {/* Syntax Highlighted Presentation Layer */}
              {diffContent && (
                <div
                  ref={highlightRef}
                  aria-hidden="true"
                  style={{
                    position: 'absolute',
                    inset: 0,
                    padding: '14px 16px',
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: '12.5px',
                    lineHeight: '22px',
                    letterSpacing: '-0.01em',
                    tabSize: 4,
                    boxSizing: 'border-box',
                    overflow: 'hidden',
                    pointerEvents: 'none',
                    zIndex: 1,
                  }}
                >
                  {lines.map((line, idx) => renderDiffSyntaxLine(line, idx))}
                </div>
              )}

              {/* Code Input */}
              <textarea
                ref={textareaRef}
                className={`code-editor-textarea ${diffContent ? 'has-content' : ''}`}
                value={diffContent}
                onChange={e => setDiffContent(e.target.value)}
                onScroll={handleScroll}
                onKeyDown={handleEditorKeyDown}
                placeholder={`# Paste a Git diff or drop a .diff / .patch file here
#
# diff --git a/app.py b/app.py
# --- a/app.py
# +++ b/app.py
# @@ -1,4 +1,4 @@
# -  subtotal = unit_price + quantity
# +  subtotal = unit_price * quantity`}
                spellCheck={false}
                style={{
                  position: 'relative',
                  width: '100%',
                  minHeight: '500px',
                  height: '100%',
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  color: diffContent ? 'transparent' : '#f4f4f5',
                  caretColor: '#ffffff',
                  fontSize: '12.5px',
                  fontFamily: "'JetBrains Mono', monospace",
                  lineHeight: '22px',
                  letterSpacing: '-0.01em',
                  padding: '14px 16px',
                  resize: 'none',
                  whiteSpace: 'pre',
                  overflowWrap: 'normal',
                  overflowX: 'auto',
                  boxSizing: 'border-box',
                  tabSize: 4,
                  zIndex: 2,
                }}
              />
            </div>
          </div>

          {/* Editor Footer Status Bar */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '7px 14px',
            background: '#0a0a0d',
            borderTop: '1px solid #19191e',
            fontSize: '10.5px',
            color: '#71717a',
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            <div>
              Format: <span style={{ color: '#d4d4d8' }}>
                {isDiffFormat
                  ? 'Git Unified Diff'
                  : (language ? `${language} Source File` : (uploadedFile ? `${uploadedFile.name.split('.').pop()?.toUpperCase()} File` : 'Source Code'))}
              </span>
            </div>
            <div>
              {uploadedFile ? (
                <span style={{ color: '#4ade80' }}>● {uploadedFile.name} loaded</span>
              ) : activeScenarioObj ? (
                <span style={{ color: '#ffffff' }}>● {activeScenarioObj.title} scenario active</span>
              ) : diffContent ? (
                <span style={{ color: '#ffffff' }}>● Ready to analyze</span>
              ) : (
                <span style={{ color: '#52525b' }}>Awaiting diff input...</span>
              )}
            </div>
          </div>
        </div>

        {/* AI Prompt Bar below the Code Window */}
        {(() => {
          const isPromptActive = promptFocused || focusMenuOpen || langMenuOpen;
          return (
            <div
              onClick={e => {
                const target = e.target as HTMLElement;
                if (!target.closest('button') && !target.closest('.dropdown-popover')) {
                  promptTextareaRef.current?.focus();
                }
              }}
              style={{
                background: '#09090c',
                border: `1px solid ${isPromptActive ? 'rgba(255, 255, 255, 0.28)' : '#1c1c22'}`,
                borderRadius: '8px',
                padding: '12px 16px',
                boxShadow: isPromptActive
                  ? '0 4px 20px rgba(0, 0, 0, 0.55)'
                  : '0 4px 16px rgba(0, 0, 0, 0.45)',
                transition: 'all 0.15s ease',
                cursor: 'text',
              }}
            >
              {/* Top Prompt Input Area */}
              <div>
                <textarea
                  ref={promptTextareaRef}
                  className="prompt-bar-textarea"
                  value={instructions}
                  onChange={e => setInstructions(e.target.value)}
                  onFocus={() => setPromptFocused(true)}
                  onBlur={() => setPromptFocused(false)}
                  onKeyDown={e => {
                    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
                      e.preventDefault();
                      handleSubmit();
                    }
                  }}
                  placeholder="Ask CodeLens AI or add review instructions (e.g. Focus on memory safety, OWASP vulnerabilities, verify concurrency edge cases)..."
                  rows={2}
                  style={{
                    width: '100%',
                    background: 'transparent',
                    border: 'none',
                    outline: 'none',
                    color: '#ffffff',
                    fontSize: '13px',
                    lineHeight: '1.5',
                    fontFamily: "'Inter', sans-serif",
                    resize: 'none',
                    boxSizing: 'border-box',
                    padding: '2px 0 6px 0',
                    display: 'block',
                  }}
                />
              </div>

          {/* Unified Controls Bar without dividing line */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '10px',
            marginTop: '6px',
          }}>
            {/* Left Controls: Custom Pill Dropdowns for Focus and Language */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              {/* Focus Menu Trigger & Popover */}
              {(() => {
                const currentFocusOption = FOCUS_OPTIONS.find(opt => opt.value === focus) || FOCUS_OPTIONS[0];
                const CurrentFocusIcon = currentFocusOption.icon;
                return (
                  <div ref={focusMenuRef} style={{ position: 'relative' }}>
                    <button
                      type="button"
                      onClick={() => {
                        setFocusMenuOpen(prev => !prev);
                        setLangMenuOpen(false);
                      }}
                      style={{
                        background: focusMenuOpen ? '#1a1a22' : '#121217',
                        border: `1px solid ${focusMenuOpen ? '#3e3e4e' : '#23232c'}`,
                        borderRadius: '6px',
                        padding: '6px 11px',
                        color: focusMenuOpen ? '#ffffff' : '#e4e4e7',
                        fontSize: '12px',
                        fontWeight: 500,
                        fontFamily: "'Inter', sans-serif",
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '7px',
                        cursor: 'pointer',
                        transition: 'all 0.12s ease',
                      }}
                      onMouseEnter={e => {
                        if (!focusMenuOpen) {
                          e.currentTarget.style.borderColor = '#343442';
                          e.currentTarget.style.background = '#17171f';
                        }
                      }}
                      onMouseLeave={e => {
                        if (!focusMenuOpen) {
                          e.currentTarget.style.borderColor = '#23232c';
                          e.currentTarget.style.background = '#121217';
                        }
                      }}
                    >
                      <CurrentFocusIcon size={13} color="#a1a1aa" />
                      <span>{currentFocusOption.label}</span>
                      <ChevronDown
                        size={12}
                        color="#71717a"
                        style={{
                          transform: focusMenuOpen ? 'rotate(180deg)' : 'none',
                          transition: 'transform 0.15s ease',
                          marginLeft: '1px',
                        }}
                      />
                    </button>

                    {/* Focus Popover */}
                    {focusMenuOpen && (
                      <div style={{
                        position: 'absolute',
                        bottom: 'calc(100% + 8px)',
                        left: 0,
                        minWidth: '190px',
                        background: '#111116',
                        border: '1px solid #282834',
                        borderRadius: '8px',
                        padding: '5px',
                        boxShadow: '0 12px 36px rgba(0, 0, 0, 0.75)',
                        zIndex: 60,
                      }}>
                        <div style={{
                          padding: '5px 8px 6px',
                          fontSize: '10px',
                          fontWeight: 600,
                          color: '#71717a',
                          textTransform: 'uppercase',
                          letterSpacing: '0.06em',
                          fontFamily: "'JetBrains Mono', monospace",
                        }}>
                          Review Focus
                        </div>
                        {FOCUS_OPTIONS.map(opt => {
                          const Icon = opt.icon;
                          const isSelected = focus === opt.value;
                          return (
                            <div
                              key={opt.value}
                              onClick={() => {
                                setFocus(opt.value);
                                setFocusMenuOpen(false);
                              }}
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                padding: '6px 9px',
                                borderRadius: '5px',
                                background: isSelected ? '#1c1c25' : 'transparent',
                                color: isSelected ? '#ffffff' : '#a1a1aa',
                                fontSize: '12px',
                                fontFamily: "'Inter', sans-serif",
                                cursor: 'pointer',
                                transition: 'all 0.1s ease',
                              }}
                              onMouseEnter={e => {
                                if (!isSelected) {
                                  e.currentTarget.style.background = '#181820';
                                  e.currentTarget.style.color = '#ffffff';
                                }
                              }}
                              onMouseLeave={e => {
                                if (!isSelected) {
                                  e.currentTarget.style.background = 'transparent';
                                  e.currentTarget.style.color = '#a1a1aa';
                                }
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <Icon size={13} color={isSelected ? '#ffffff' : '#71717a'} />
                                <span>{opt.label}</span>
                              </div>
                              {isSelected && <Check size={13} color="#ffffff" />}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Language Menu Trigger & Popover */}
              <div ref={langMenuRef} style={{ position: 'relative' }}>
                <button
                  type="button"
                  onClick={() => {
                    setLangMenuOpen(prev => !prev);
                    setFocusMenuOpen(false);
                  }}
                  style={{
                    background: langMenuOpen ? '#1a1a22' : '#121217',
                    border: `1px solid ${langMenuOpen ? '#3e3e4e' : '#23232c'}`,
                    borderRadius: '6px',
                    padding: '6px 11px',
                    color: langMenuOpen ? '#ffffff' : '#e4e4e7',
                    fontSize: '12px',
                    fontWeight: 500,
                    fontFamily: "'Inter', sans-serif",
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '7px',
                    cursor: 'pointer',
                    transition: 'all 0.12s ease',
                  }}
                  onMouseEnter={e => {
                    if (!langMenuOpen) {
                      e.currentTarget.style.borderColor = '#343442';
                      e.currentTarget.style.background = '#17171f';
                    }
                  }}
                  onMouseLeave={e => {
                    if (!langMenuOpen) {
                      e.currentTarget.style.borderColor = '#23232c';
                      e.currentTarget.style.background = '#121217';
                    }
                  }}
                >
                  <FileCode2 size={13} color="#a1a1aa" />
                  <span>{language || 'Auto-detect'}</span>
                  <ChevronDown
                    size={12}
                    color="#71717a"
                    style={{
                      transform: langMenuOpen ? 'rotate(180deg)' : 'none',
                      transition: 'transform 0.15s ease',
                      marginLeft: '1px',
                    }}
                  />
                </button>

                {/* Language Popover */}
                {langMenuOpen && (
                  <div style={{
                    position: 'absolute',
                    bottom: 'calc(100% + 8px)',
                    left: 0,
                    minWidth: '160px',
                    maxHeight: '230px',
                    overflowY: 'auto',
                    background: '#111116',
                    border: '1px solid #282834',
                    borderRadius: '8px',
                    padding: '5px',
                    boxShadow: '0 12px 36px rgba(0, 0, 0, 0.75)',
                    zIndex: 60,
                  }}>
                    <div style={{
                      padding: '5px 8px 6px',
                      fontSize: '10px',
                      fontWeight: 600,
                      color: '#71717a',
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      fontFamily: "'JetBrains Mono', monospace",
                    }}>
                      Target Language
                    </div>
                    {LANGUAGES.map(l => {
                      const isSelected = language === l;
                      return (
                        <div
                          key={l}
                          onClick={() => {
                            setLanguage(l);
                            setLangMenuOpen(false);
                          }}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '6px 9px',
                            borderRadius: '5px',
                            background: isSelected ? '#1c1c25' : 'transparent',
                            color: isSelected ? '#ffffff' : '#a1a1aa',
                            fontSize: '12px',
                            fontFamily: "'Inter', sans-serif",
                            cursor: 'pointer',
                            transition: 'all 0.1s ease',
                          }}
                          onMouseEnter={e => {
                            if (!isSelected) {
                              e.currentTarget.style.background = '#181820';
                              e.currentTarget.style.color = '#ffffff';
                            }
                          }}
                          onMouseLeave={e => {
                            if (!isSelected) {
                              e.currentTarget.style.background = 'transparent';
                              e.currentTarget.style.color = '#a1a1aa';
                            }
                          }}
                        >
                          <span>{l || 'Auto-detect'}</span>
                          {isSelected && <Check size={13} color="#ffffff" />}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Right Controls: Analyze Button with Shortcut on Hover */}
            <div style={{ position: 'relative' }}>
              {showShortcutTooltip && (
                <div style={{
                  position: 'absolute',
                  bottom: 'calc(100% + 8px)',
                  right: '0',
                  background: '#141419',
                  border: '1px solid #282834',
                  borderRadius: '6px',
                  padding: '5px 10px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  boxShadow: '0 4px 16px rgba(0, 0, 0, 0.6)',
                  whiteSpace: 'nowrap',
                  zIndex: 50,
                  pointerEvents: 'none',
                }}>
                  <span style={{ fontSize: '11px', color: '#a1a1aa', fontFamily: "'Inter', sans-serif" }}>Shortcut:</span>
                  <kbd style={{
                    background: '#1f1f27',
                    border: '1px solid #323242',
                    borderRadius: '3px',
                    padding: '2px 5px',
                    fontSize: '10px',
                    color: '#ffffff',
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>⌘</kbd>
                  <span style={{ color: '#52525b', fontSize: '11px' }}>+</span>
                  <kbd style={{
                    background: '#1f1f27',
                    border: '1px solid #323242',
                    borderRadius: '3px',
                    padding: '2px 5px',
                    fontSize: '10px',
                    color: '#ffffff',
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>Enter</kbd>
                </div>
              )}

              <button
                onClick={handleSubmit}
                disabled={loading}
                onMouseEnter={() => {
                  setShowShortcutTooltip(true);
                  if (!loading) {
                    const btn = document.getElementById('analyze-code-btn');
                    if (btn) btn.style.background = '#e4e4e7';
                  }
                }}
                onMouseLeave={() => {
                  setShowShortcutTooltip(false);
                  if (!loading) {
                    const btn = document.getElementById('analyze-code-btn');
                    if (btn) btn.style.background = '#ffffff';
                  }
                }}
                id="analyze-code-btn"
                style={{
                  background: loading ? '#222228' : '#ffffff',
                  color: loading ? '#71717a' : '#000000',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '9px 18px',
                  fontSize: '12.5px',
                  fontWeight: 700,
                  letterSpacing: '-0.01em',
                  fontFamily: "'Inter', sans-serif",
                  cursor: loading ? 'not-allowed' : 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '7px',
                  boxShadow: loading ? 'none' : '0 2px 10px rgba(255, 255, 255, 0.12)',
                  transition: 'background 0.12s ease',
                }}
              >
                {loading ? <LoadingSpinner size={14} /> : <Play size={13} fill="currentColor" />}
                <span>{loading ? 'Analyzing Code Changes...' : 'Analyze Code'}</span>
              </button>
            </div>
          </div>
        </div>
      );
    })()}

      </div>
    </div>
  );
}
