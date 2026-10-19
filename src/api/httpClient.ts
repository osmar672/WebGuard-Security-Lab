import { apiBaseUrl, isValidApiBaseUrl } from './config';

export class ApiRequestError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'ApiRequestError';
  }
}

export type Decoder<T> = (input: unknown) => T;

const REQUEST_TIMEOUT_MS = 8_000;

/** Centralized, typed-by-decoder HTTP client. No cookies or secrets are sent. */
export async function getJson<T>(path: string, decode: Decoder<T>): Promise<T> {
  if (!path.trim()) {
    throw new ApiRequestError('API endpoint is not configured. Waiting for the approved Phase 0 API contract.');
  }
  if (!apiBaseUrl || !isValidApiBaseUrl(apiBaseUrl)) {
    throw new ApiRequestError('API base URL is missing or invalid. Set VITE_API_BASE_URL.');
  }

  let url: URL;
  try {
    url = new URL(path, `${apiBaseUrl.replace(/\/$/, '')}/`);
  } catch {
    throw new ApiRequestError('Configured API endpoint is not a valid URL or path.');
  }
  if (url.origin !== new URL(apiBaseUrl).origin) {
    throw new ApiRequestError('API endpoint must remain on the configured API origin.');
  }

  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    let response: Response;
    try {
      response = await fetch(url, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
      });
    } catch {
      if (controller.signal.aborted) {
        throw new ApiRequestError(`Request timed out after ${REQUEST_TIMEOUT_MS / 1000} seconds.`);
      }
      throw new ApiRequestError('Could not connect to the API. Check the backend URL and CORS configuration.');
    }

    if (!response.ok) {
      throw new ApiRequestError(`API returned HTTP ${response.status}.`, response.status);
    }

    let payload: unknown;
    try {
      payload = await response.json() as unknown;
    } catch {
      throw new ApiRequestError('API returned invalid JSON. Confirm the response schema with the backend owner.');
    }

    try {
      return decode(payload);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unexpected response format.';
      throw new ApiRequestError(`API response does not match the frontend placeholder schema: ${message}`);
    }
  } finally {
    window.clearTimeout(timeoutId);
  }
}
