import { getJson, postJson } from './httpClient';
import { apiPaths } from './config';

export type AITask = 'process_review' | 'audit_summary' | 'finding_triage' | 'remediation_plan' | 'general';

export interface AIStatus {
  configured: boolean;
  mode: 'remote_model' | 'local_rules';
  provider: string;
  model: string | null;
  capabilities: string[];
  privacy_note: string;
}

export interface AIAssistResponse {
  task: AITask;
  answer: string;
  mode: 'remote_model' | 'local_rules';
  provider: string;
  model: string | null;
  generated_at: string;
  disclaimer: string;
}

function unwrapData<T>(payload: unknown, validate: (value: unknown) => T): T {
  if (!payload || typeof payload !== 'object' || !('data' in payload)) {
    throw new Error('The AI API returned an invalid response envelope.');
  }
  return validate((payload as { data: unknown }).data);
}

function decodeStatus(payload: unknown): AIStatus {
  return unwrapData(payload, (value) => {
    if (!value || typeof value !== 'object') throw new Error('AI status is missing.');
    const candidate = value as Partial<AIStatus>;
    if (typeof candidate.configured !== 'boolean' || !['remote_model', 'local_rules'].includes(candidate.mode ?? '')
      || typeof candidate.provider !== 'string' || !Array.isArray(candidate.capabilities)
      || typeof candidate.privacy_note !== 'string') throw new Error('AI status schema is invalid.');
    return candidate as AIStatus;
  });
}

function decodeAssist(payload: unknown): AIAssistResponse {
  return unwrapData(payload, (value) => {
    if (!value || typeof value !== 'object') throw new Error('AI response is missing.');
    const candidate = value as Partial<AIAssistResponse>;
    if (typeof candidate.answer !== 'string' || typeof candidate.task !== 'string'
      || !['remote_model', 'local_rules'].includes(candidate.mode ?? '')
      || typeof candidate.provider !== 'string' || typeof candidate.generated_at !== 'string'
      || typeof candidate.disclaimer !== 'string') throw new Error('AI response schema is invalid.');
    return candidate as AIAssistResponse;
  });
}

export function getAIStatus(): Promise<AIStatus> {
  return getJson(apiPaths.aiStatus, decodeStatus);
}

export function requestAIAssistance(input: { task: AITask; question?: string; audit_id?: string }): Promise<AIAssistResponse> {
  return postJson(apiPaths.aiAssist, input, decodeAssist, false, 65_000);
}
