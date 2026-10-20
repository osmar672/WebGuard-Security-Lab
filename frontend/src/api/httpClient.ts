import { apiBaseUrl, isValidApiBaseUrl } from './config';
import { clearAccessToken, getAccessToken } from './session';

export class ApiRequestError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = 'ApiRequestError';
  }
}

export type Decoder<T> = (input: unknown) => T;
const REQUEST_TIMEOUT_MS = 8_000;

function makeUrl(path: string): URL {
  if (!path.trim()) throw new ApiRequestError('API endpoint is not configured.');
  if (!isValidApiBaseUrl(apiBaseUrl)) throw new ApiRequestError('API base URL is invalid. Set VITE_API_BASE_URL.');
  const origin = apiBaseUrl ? apiBaseUrl.replace(/\/$/, '') : window.location.origin;
  let url: URL;
  try { url = new URL(path, `${origin}/`); } catch {
    throw new ApiRequestError('Configured API endpoint is not a valid URL or path.');
  }
  if (url.origin !== new URL(origin).origin) throw new ApiRequestError('API endpoint must remain on the configured API origin.');
  return url;
}

async function requestJson<T>(
  method: 'GET' | 'POST',
  path: string,
  decode: Decoder<T>,
  body?: unknown,
  anonymous = false,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<T> {
  const url = makeUrl(path);
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
  const token = anonymous ? null : getAccessToken();
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
      });
    } catch {
      if (controller.signal.aborted) throw new ApiRequestError(`Request timed out after ${timeoutMs / 1000} seconds.`);
      throw new ApiRequestError('Could not connect to the API. Check that the backend is running.');
    }

    if (!response.ok) {
      if (response.status === 401 && token) {
        clearAccessToken();
        window.dispatchEvent(new CustomEvent('webguard:unauthorized'));
      }
      let serverMessage = '';
      try {
        const errorPayload: unknown = await response.json();
        if (typeof errorPayload === 'object' && errorPayload !== null && 'error' in errorPayload) {
          const error = (errorPayload as { error?: { message?: unknown } }).error;
          if (typeof error?.message === 'string') serverMessage = error.message;
        }
        if (!serverMessage && typeof errorPayload === 'object' && errorPayload !== null && 'detail' in errorPayload) {
          const detail = (errorPayload as { detail?: unknown }).detail;
          if (typeof detail === 'string') serverMessage = detail;
        }
      } catch { /* response body may be empty or non-JSON */ }
      throw new ApiRequestError(serverMessage || `API returned HTTP ${response.status}.`, response.status);
    }

    let payload: unknown;
    try { payload = await response.json() as unknown; } catch {
      throw new ApiRequestError('API returned invalid JSON.');
    }
    try { return decode(payload); } catch (error) {
      const message = error instanceof Error ? error.message : 'Unexpected response format.';
      throw new ApiRequestError(`API response schema validation failed: ${message}`);
    }
  } finally {
    window.clearTimeout(timeoutId);
  }
}

export function getJson<T>(path: string, decode: Decoder<T>): Promise<T> {
  return requestJson('GET', path, decode);
}

export function postJson<T>(path: string, body: unknown, decode: Decoder<T>, anonymous = false, timeoutMs = REQUEST_TIMEOUT_MS): Promise<T> {
  return requestJson('POST', path, decode, body, anonymous, timeoutMs);
}
