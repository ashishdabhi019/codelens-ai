import React, { useState } from 'react';
import type { Finding } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { Copy, Check, FileCode2 } from 'lucide-react';
import { useToast } from '../context/ToastContext';

const TOKEN_REGEX = /(#[^\n]*|\/\/[^\n]*)|(f?"""[\s\S]*?"""|f?'''[\s\S]*?'''|f?"(?:\\.|[^"\\])*"|f?'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(\b(?:def|class|function|async|await|return|yield|import|from|as|export|default|const|let|var|type|interface|package|func)\b)|(\b(?:if|elif|else|for|while|try|except|finally|with|match|case|switch|break|continue|throw|raise)\b)|(\b(?:and|or|not|in|is)\b)|(\b(?:int|str|float|bool|list|dict|set|tuple|void|number|string|boolean|any|unknown|never)\b)|(\b(?:True|False|None|true|false|null|undefined|nil)\b)|(\b[A-Z][a-zA-Z0-9_]*\b)|(\b(?:self|this)\b)|(\b\d+(?:\.\d+)?\b)|(\b[a-zA-Z_][a-zA-Z0-9_]*(?=\s*\())/g;

function highlightTokens(text: string, defaultColor = '#d4d4d4'): React.ReactNode {
  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  TOKEN_REGEX.lastIndex = 0;

  while ((match = TOKEN_REGEX.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(
        <span key={`txt-${lastIndex}`} style={{ color: defaultColor }}>
          {text.substring(lastIndex, match.index)}
        </span>
      );
    }

    if (match[1]) {
      parts.push(
        <span key={`comm-${match.index}`} style={{ color: '#6a9955', fontStyle: 'italic' }}>
          {match[1]}
        </span>
      );
    } else if (match[2]) {
      parts.push(
        <span key={`str-${match.index}`} style={{ color: '#ce9178' }}>
          {match[2]}
        </span>
      );
    } else if (match[11]) {
      parts.push(
        <span key={`fn-${match.index}`} style={{ color: '#dcdcaa', fontWeight: 600 }}>
          {match[11]}
        </span>
      );
    } else if (match[3]) {
      parts.push(
        <span key={`kw-${match.index}`} style={{ color: '#569cd6', fontWeight: 600 }}>
          {match[3]}
        </span>
      );
    } else if (match[4]) {
      parts.push(
        <span key={`ctrl-${match.index}`} style={{ color: '#c586c0', fontWeight: 600 }}>
          {match[4]}
        </span>
      );
    } else if (match[5]) {
      parts.push(
        <span key={`op-${match.index}`} style={{ color: '#569cd6' }}>
          {match[5]}
        </span>
      );
    } else if (match[6] || match[8]) {
      parts.push(
        <span key={`typ-${match.index}`} style={{ color: '#4ec9b0', fontWeight: 600 }}>
          {match[6] || match[8]}
        </span>
      );
    } else if (match[7]) {
      parts.push(
        <span key={`lit-${match.index}`} style={{ color: '#569cd6' }}>
          {match[7]}
        </span>
      );
    } else if (match[9]) {
      parts.push(
        <span key={`slf-${match.index}`} style={{ color: '#9cdcfe', fontStyle: 'italic' }}>
          {match[9]}
        </span>
      );
    } else if (match[10]) {
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

interface InlineCodeReviewProps {
  diffContent: string;
  filename?: string;
  findings: Finding[];
}

export function InlineCodeReview({ diffContent, filename, findings }: InlineCodeReviewProps) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const toast = useToast();

  const copyToClipboard = (text: string, index: number, title?: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedIndex(index);
      toast.success(
        title ? `Fix for "${title}" copied to clipboard` : 'Suggested fix copied to clipboard',
        'Copied to Clipboard'
      );
      setTimeout(() => setCopiedIndex(null), 2000);
    }).catch(() => {
      toast.error('Failed to copy to clipboard');
    });
  };

  // Determine if content is git diff format
  const isDiff = diffContent.includes('--- ') && diffContent.includes('+++ ') && diffContent.includes('@@');

  // Strip git diff headers so the user sees clean code starting directly at Line 1.
  // This matches GitHub PR / Devin AI behavior where raw diff headers aren't treated as code lines.
  let displayCode = diffContent;
  if (isDiff) {
    const lines = diffContent.split('\n');
    const codeStartIndex = lines.findIndex(l => l.startsWith('@@'));
    if (codeStartIndex !== -1) {
      displayCode = lines.slice(codeStartIndex + 1).join('\n');
    }
  }

  const rawLines = displayCode.split('\n');

  interface ParsedLine {
    rawIndex: number;
    rawText: string;
    cleanText: string;
    isAdd: boolean;
    isDel: boolean;
    targetLineNum: number | null;
  }

  let currentTargetLine = 1;
  const parsedLines: ParsedLine[] = [];
  const targetLineMap = new Map<number, string>();

  for (let idx = 0; idx < rawLines.length; idx++) {
    const line = rawLines[idx];
    if (line.startsWith('@@')) {
      const match = /@@ -\d+(?:,\d+)? \+(\d+)/.exec(line);
      if (match) {
        currentTargetLine = parseInt(match[1], 10);
      }
      continue;
    }

    const isAdd = line.startsWith('+') && !line.startsWith('+++');
    const isDel = line.startsWith('-') && !line.startsWith('---');
    const cleanText = (isAdd || isDel || line.startsWith(' ')) ? line.slice(1) : line;

    if (isDel) {
      parsedLines.push({
        rawIndex: idx,
        rawText: line,
        cleanText,
        isAdd: false,
        isDel: true,
        targetLineNum: null,
      });
    } else {
      const targetNum = currentTargetLine++;
      targetLineMap.set(targetNum, cleanText);
      parsedLines.push({
        rawIndex: idx,
        rawText: line,
        cleanText,
        isAdd,
        isDel: false,
        targetLineNum: targetNum,
      });
    }
  }

  // Group findings by target line number to anchor inline comment cards directly beneath the offending code
  const findingsByLine = new Map<number, Finding[]>();
  const globalFindings: Finding[] = []; // File-level issues (e.g. missing test coverage or overall security notes)

  findings.forEach(f => {
    if (f.line != null) {
      const existing = findingsByLine.get(f.line) || [];
      existing.push(f);
      findingsByLine.set(f.line, existing);
    } else {
      globalFindings.push(f);
    }
  });

  const getSeverityBorder = (sev: string) => {
    switch (sev) {
      case 'critical': return '#f43f5e';
      case 'high': return '#fb923c';
      case 'medium': return '#38bdf8';
      case 'low': return '#4ade80';
      default: return '#30363d';
    }
  };

  const renderFindingCard = (finding: Finding, cardKey: number | string) => {
    const isCopied = copiedIndex === cardKey;
    const accentColor = getSeverityBorder(finding.severity);

    return (
      <div
        key={cardKey}
        style={{
          margin: '10px 18px 16px 18px',
          background: '#0d1117',
          border: `1px solid ${accentColor}44`,
          borderLeft: `4px solid ${accentColor}`,
          borderRadius: '8px',
          overflow: 'hidden',
          boxShadow: '0 8px 30px rgba(0, 0, 0, 0.7)',
          fontFamily: "'Inter', sans-serif",
          animation: 'toastSlideDown 0.2s ease',
        }}
      >
        {/* Comment Header */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 14px',
          background: '#161b22',
          borderBottom: '1px solid #21262d',
          flexWrap: 'wrap',
          gap: '8px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '9px' }}>
            {/* Bot Avatar */}
            <div style={{
              width: '24px',
              height: '24px',
              borderRadius: '6px',
              background: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 1px 4px rgba(255, 255, 255, 0.15)',
              flexShrink: 0,
            }}>
              <svg width="14" height="14" viewBox="0 0 18 18" fill="none">
                <path d="M4 4.5L9 9L4 13.5" stroke="#000000" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
                <line x1="10.5" y1="13.5" x2="15" y2="13.5" stroke="#000000" strokeWidth="2.2" strokeLinecap="round"/>
              </svg>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ color: '#ffffff', fontSize: '13px', fontWeight: 600, letterSpacing: '-0.01em' }}>
                codelens-ai
              </span>
              <span style={{
                background: '#21262d',
                border: '1px solid #30363d',
                color: '#8b949e',
                fontSize: '10px',
                padding: '1px 6px',
                borderRadius: '4px',
                fontWeight: 600,
                textTransform: 'uppercase',
              }}>
                bot
              </span>
              <span style={{ color: '#8b949e', fontSize: '11px' }}>
                reviewed line {finding.line ?? 'change'}
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {finding.id && (
              <span style={{
                color: '#8b949e',
                fontSize: '10.5px',
                fontFamily: "'JetBrains Mono', monospace",
                background: '#1c2128',
                padding: '2px 6px',
                borderRadius: '4px',
                border: '1px solid #30363d',
              }}>
                #{finding.id}
              </span>
            )}
            <span style={{
              color: '#8b949e',
              fontSize: '10.5px',
              fontFamily: "'JetBrains Mono', monospace",
              background: '#1c2128',
              padding: '2px 7px',
              borderRadius: '4px',
            }}>
              {finding.category.toUpperCase()}
            </span>
            <SeverityBadge severity={finding.severity} />
          </div>
        </div>

        {/* Comment Body */}
        <div style={{ padding: '14px 16px' }}>
          {/* Finding Title */}
          <div style={{
            color: '#ffffff',
            fontSize: '14px',
            fontWeight: 700,
            marginBottom: '8px',
            letterSpacing: '-0.01em',
            display: 'flex',
            alignItems: 'center',
            gap: '7px',
          }}>
            <span style={{ color: accentColor }}>●</span>
            <span>{finding.title}</span>
          </div>

          {finding.root_cause && (
            <div style={{
              marginBottom: '10px',
              fontSize: '12px',
              color: '#e6edf3',
              background: '#161b22',
              padding: '6px 10px',
              borderRadius: '4px',
              border: '1px solid #30363d',
            }}>
              <strong style={{ color: '#fb923c', fontSize: '10.5px', textTransform: 'uppercase', fontFamily: "'JetBrains Mono', monospace" }}>Root Cause: </strong>
              {finding.root_cause}
            </div>
          )}

          {/* Description */}
          <div style={{
            color: '#c9d1d9',
            fontSize: '13px',
            lineHeight: '1.6',
            marginBottom: '14px',
          }}>
            {finding.description}
          </div>

          {/* Current Faulty Code Line */}
          {(() => {
            const rawCode = finding.evidence || (finding.line != null ? targetLineMap.get(finding.line) : null);
            const currentCodeText = rawCode?.trim();
            if (!currentCodeText) return null;
            return (
              <div style={{ marginBottom: '12px' }}>
                <div style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  color: '#8b949e',
                  marginBottom: '5px',
                  fontFamily: "'Inter', sans-serif",
                }}>
                  Current code:
                </div>
                <div style={{
                  background: '#0a0d12',
                  border: '1px solid #30363d',
                  borderLeft: '3px solid #f87171',
                  borderRadius: '5px',
                  padding: '9px 12px',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '12px',
                  color: '#f87171',
                  overflowX: 'auto',
                  whiteSpace: 'pre',
                }}>
                  {rawCode}
                </div>
              </div>
            );
          })()}

          {/* Recommended Fix */}
          {finding.suggested_fix && (
            <div style={{ marginBottom: '12px' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '5px',
              }}>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  color: '#58a6ff',
                  fontFamily: "'Inter', sans-serif",
                }}>
                  Recommended fix:
                </span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(finding.suggested_fix!, typeof cardKey === 'number' ? cardKey : 999, finding.title)}
                  style={{
                    background: '#161b22',
                    border: '1px solid #30363d',
                    borderRadius: '4px',
                    color: isCopied ? '#4ade80' : '#8b949e',
                    fontSize: '11px',
                    padding: '3px 8px',
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                    fontFamily: "'Inter', sans-serif",
                    transition: 'all 0.12s ease',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.color = '#ffffff'; e.currentTarget.style.borderColor = '#484f58'; }}
                  onMouseLeave={e => { if (!isCopied) { e.currentTarget.style.color = '#8b949e'; e.currentTarget.style.borderColor = '#30363d'; } }}
                >
                  {isCopied ? <Check size={12} color="#4ade80" /> : <Copy size={12} />}
                  <span>{isCopied ? 'Copied fix!' : 'Copy fix'}</span>
                </button>
              </div>

              <div style={{
                background: '#0a0d12',
                border: '1px solid rgba(88, 166, 255, 0.25)',
                borderLeft: '3px solid #4ade80',
                borderRadius: '5px',
                padding: '9px 12px',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '12px',
                color: '#4ade80',
                overflowX: 'auto',
                whiteSpace: 'pre',
                lineHeight: '1.5',
              }}>
                {finding.suggested_fix}
              </div>
            </div>
          )}

          {/* Explanation / Recommendation Footer */}
          <div style={{
            borderTop: '1px solid #21262d',
            paddingTop: '10px',
            marginTop: '8px',
            color: '#8b949e',
            fontSize: '12px',
            lineHeight: '1.5',
          }}>
            <strong style={{ color: '#c9d1d9' }}>Why: </strong>
            {finding.recommendation || finding.impact}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div style={{
      background: '#09090c',
      border: '1px solid #222228',
      borderRadius: '8px',
      overflow: 'hidden',
      marginBottom: '28px',
      boxShadow: '0 8px 32px rgba(0, 0, 0, 0.55)',
    }}>
      {/* Code Window Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '9px 16px',
        background: '#0d0d10',
        borderBottom: '1px solid #1c1c22',
        flexWrap: 'wrap',
        gap: '8px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '9px' }}>
          <FileCode2 size={14} color="#9cdcfe" />
          <span style={{
            fontSize: '12px',
            fontWeight: 600,
            color: '#ffffff',
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            {filename || 'source.py'}
          </span>
          <span style={{
            fontSize: '11px',
            color: '#71717a',
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            {rawLines.length} lines
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            fontSize: '11.5px',
            color: findings.length > 0 ? '#fb923c' : '#4ade80',
            fontWeight: 600,
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            {findings.length} inline review finding{findings.length !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      {/* Global / File-level findings */}
      {globalFindings.length > 0 && (
        <div style={{ padding: '8px 0', borderBottom: '1px solid #1c1c22', background: '#0a0d12' }}>
          {globalFindings.map((f, i) => renderFindingCard(f, `global-${i}`))}
        </div>
      )}

      {/* Code View with Inline Findings */}
      <div style={{
        overflowX: 'auto',
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '12.5px',
        lineHeight: '22px',
        background: '#050507',
      }}>
        {parsedLines.map((lineItem, idx) => {
          const lineFindings = lineItem.targetLineNum != null
            ? findingsByLine.get(lineItem.targetLineNum)
            : undefined;
          const hasFinding = !!lineFindings && lineFindings.length > 0;
          const highestSeverity = lineFindings ? lineFindings[0].severity : null;
          const lineAccent = highestSeverity ? getSeverityBorder(highestSeverity) : null;
          const isAdd = lineItem.isAdd;
          const isDel = lineItem.isDel;
          const lineBg = hasFinding
            ? `${lineAccent}15`
            : isAdd
            ? 'rgba(74, 222, 128, 0.05)'
            : isDel
            ? 'rgba(244, 63, 94, 0.05)'
            : undefined;

          return (
            <React.Fragment key={`line-${idx}-${lineItem.targetLineNum ?? 'del'}`}>
              {/* Code Line */}
              <div style={{
                display: 'flex',
                alignItems: 'stretch',
                background: lineBg,
                borderLeft: hasFinding ? `3px solid ${lineAccent}` : '3px solid transparent',
                transition: 'background 0.12s ease',
              }}>
                {/* Gutter Line Number */}
                <div style={{
                  width: '46px',
                  padding: '0 12px 0 6px',
                  color: hasFinding ? lineAccent! : isDel ? '#f87171' : isAdd ? '#4ade80' : '#484852',
                  textAlign: 'right',
                  userSelect: 'none',
                  fontSize: '11px',
                  fontWeight: hasFinding ? 700 : 400,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'flex-end',
                  gap: '4px',
                  flexShrink: 0,
                }}>
                  {hasFinding && (
                    <span style={{
                      width: '5px',
                      height: '5px',
                      borderRadius: '50%',
                      background: lineAccent!,
                      display: 'inline-block',
                    }} />
                  )}
                  <span>{isDel ? '-' : (lineItem.targetLineNum ?? '')}</span>
                </div>

                {/* Line Code Content */}
                <div style={{
                  padding: '0 12px',
                  whiteSpace: 'pre',
                  flex: 1,
                  color: isDel ? '#f87171' : '#d4d4d4',
                }}>
                  {isAdd && (
                    <span style={{ color: '#4ade80', fontWeight: 700, marginRight: '4px' }}>+</span>
                  )}
                  {isDel && (
                    <span style={{ color: '#f87171', fontWeight: 700, marginRight: '4px' }}>-</span>
                  )}
                  {highlightTokens(lineItem.cleanText, isDel ? '#f87171' : isAdd ? '#9cdcfe' : '#d4d4d4') || '\u00A0'}
                </div>
              </div>

              {/* Inline AI Review Card(s) attached directly underneath this line */}
              {lineFindings && lineFindings.map((f, fIdx) => renderFindingCard(f, `line-${lineItem.targetLineNum}-${fIdx}`))}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

