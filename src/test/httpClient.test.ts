import { describe, expect, it, vi, afterEach } from 'vitest';
import { getJson } from '../api/httpClient';

afterEach(() => vi.unstubAllGlobals());

describe('central HTTP client', () => {
  it('rejects empty endpoint paths instead of guessing a route', async () => {
    await expect(getJson('', (value) => value)).rejects.toThrow(/endpoint is not configured/i);
  });

  it('accepts only HTTP(S) API base URLs', async () => {
    const envModule = await import('../api/config');
    expect(envModule.isValidApiBaseUrl('javascript:alert(1)')).toBe(false);
    expect(envModule.isValidApiBaseUrl('http://127.0.0.1:8000')).toBe(true);
  });
});
