export interface Finding {
  id?: string;
  title: string;
  category: 'bug' | 'security' | 'performance' | 'testing' | 'style' | 'maintainability';
  severity: 'critical' | 'high' | 'medium' | 'low';
  file: string;
  line?: number;
  root_cause?: string;
  evidence?: string;
  description: string;
  impact: string;
  recommendation: string;
  suggested_fix?: string;
  confidence: number;
  reproduction_scenario?: string;
  fix_verification_status?: 'validated_syntax' | 'passed_tests' | 'proposed' | 'rejected';
}

export interface ReviewResult {
  summary: string;
  overall_status: 'approved' | 'changes_requested' | 'needs_attention';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  files_reviewed: number;
  findings: Finding[];
  missing_tests: string[];
  positive_observations: string[];
  deterministic_findings: Finding[];
  llm_available: boolean;
  partial_analysis?: boolean;
  unverified_findings_count?: number;
}

export interface ReviewResponse {
  id: string;
  created_at: string;
  result: ReviewResult;
  processing_time_seconds: number;
  diff_content?: string;
  filename?: string;
}

export interface ReviewHistoryItem {
  id: string;
  created_at: string;
  filename: string | null;
  summary: string;
  findings_count: number;
  overall_status: string;
  risk_level: string;
}

export interface ReviewRequest {
  diff_content: string;
  focus: 'all' | 'bugs' | 'security' | 'performance' | 'testing' | 'style';
  language?: string;
  additional_instructions?: string;
  filename?: string;
}
