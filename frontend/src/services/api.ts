import axios from 'axios';
import type { ReviewRequest, ReviewResponse, ReviewHistoryItem } from '../types';

const api = axios.create({
  baseURL: '/api',
  timeout: 180000,
});

export const submitReview = (request: ReviewRequest): Promise<ReviewResponse> =>
  api.post<ReviewResponse>('/reviews', request).then(r => r.data);

export const submitReviewFile = (
  file: File,
  focus: string = 'all',
  language?: string,
  instructions?: string,
): Promise<ReviewResponse> => {
  const form = new FormData();
  form.append('file', file);
  form.append('focus', focus);
  if (language) form.append('language', language);
  if (instructions) form.append('additional_instructions', instructions);
  return api.post<ReviewResponse>('/reviews/upload', form).then(r => r.data);
};

export const getReviews = (): Promise<ReviewHistoryItem[]> =>
  api.get<ReviewHistoryItem[]>('/reviews').then(r => r.data);

export const getReview = (id: string): Promise<ReviewResponse> =>
  api.get<ReviewResponse>(`/reviews/${id}`).then(r => r.data);

export const deleteReview = (id: string): Promise<void> =>
  api.delete(`/reviews/${id}`).then(() => undefined);

export function extractErrorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) {
      return detail.map((d: { msg?: string }) => d.msg || JSON.stringify(d)).join('; ');
    }
    if (err.response?.status === 413) {
      return 'Diff file is too large. Maximum supported size is 500KB.';
    }
    if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
      return 'Request timed out after 3 minutes. The LLM might be busy or offline.';
    }
    if (!err.response) {
      return 'Cannot reach the backend server. Please verify backend is running on http://localhost:8000.';
    }
    return err.response?.data?.message || err.message || 'An unexpected error occurred.';
  }
  if (err instanceof Error) return err.message;
  return 'An unexpected error occurred.';
}
