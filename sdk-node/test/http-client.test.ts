import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HttpClient } from '../src/http-client.js';
import type { ValidatedConfig } from '../src/config.js';

describe('HTTP Client with Retry Logic', () => {
  let config: ValidatedConfig;

  beforeEach(() => {
    config = {
      serviceUrl: 'https://sigil.example.com',
      apiKey: 'sgk_test_' + 'a'.repeat(64),
      rejectUnauthorized: true,
      maxRetries: 3,
      retryDelays: [100, 200, 400],
      timeout: 10000
    };
  });

  describe('Request Construction', () => {
    it('should add Bearer token to Authorization header', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: 'success' })
      });
      global.fetch = fetchMock;

      await client.post('/challenge', { test: 'data' });

      expect(fetchMock).toHaveBeenCalledWith(
        'https://sigil.example.com/challenge',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': `Bearer ${config.apiKey}`
          })
        })
      );
    });

    it('should set Content-Type to application/json', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: 'success' })
      });
      global.fetch = fetchMock;

      await client.post('/challenge', { test: 'data' });

      expect(fetchMock).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          })
        })
      );
    });

    it('should set request timeout', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: 'success' })
      });
      global.fetch = fetchMock;

      await client.post('/challenge', { test: 'data' });

      expect(fetchMock).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          signal: expect.any(Object)  // AbortSignal
        })
      );
    });
  });

  describe('Retry Logic', () => {
    it('should retry on 429 (rate limited)', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          json: async () => ({ error: { code: 'RATE_LIMITED' } })
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ result: 'success' })
        });
      global.fetch = fetchMock;

      const result = await client.post('/challenge', {});

      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(result).toEqual({ result: 'success' });
    });

    it('should retry on 500 (server error)', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          json: async () => ({ error: { code: 'INTERNAL_ERROR' } })
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ result: 'success' })
        });
      global.fetch = fetchMock;

      const result = await client.post('/challenge', {});

      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(result).toEqual({ result: 'success' });
    });

    it('should NOT retry on 400 (client error)', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({
          error: {
            code: 'INVALID_REQUEST',
            message: 'Invalid fingerprint'
          }
        })
      });
      global.fetch = fetchMock;

      await expect(client.post('/challenge', {})).rejects.toThrow();
      expect(fetchMock).toHaveBeenCalledTimes(1);  // No retry
    });

    it('should NOT retry on 401 (unauthorized)', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        json: async () => ({
          error: { code: 'UNAUTHORIZED' }
        })
      });
      global.fetch = fetchMock;

      await expect(client.post('/challenge', {})).rejects.toThrow();
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('should exhaust retries and throw', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ error: { code: 'INTERNAL_ERROR' } })
      });
      global.fetch = fetchMock;

      await expect(client.post('/challenge', {})).rejects.toThrow();
      expect(fetchMock).toHaveBeenCalledTimes(4);  // 1 initial + 3 retries
    });

    it('should apply exponential backoff delays', async () => {
      vi.useFakeTimers();
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ error: { code: 'INTERNAL_ERROR' } })
      });
      global.fetch = fetchMock;

      const promise = client.post('/challenge', {}).catch(() => {});  // Catch to prevent unhandled rejection

      // Let initial request complete
      await vi.runOnlyPendingTimersAsync();
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // First retry after 100ms
      await vi.advanceTimersByTimeAsync(100);
      expect(fetchMock).toHaveBeenCalledTimes(2);

      // Second retry after 200ms
      await vi.advanceTimersByTimeAsync(200);
      expect(fetchMock).toHaveBeenCalledTimes(3);

      // Third retry after 400ms
      await vi.advanceTimersByTimeAsync(400);
      expect(fetchMock).toHaveBeenCalledTimes(4);

      await promise;
      vi.useRealTimers();
    });
  });

  describe('Error Handling', () => {
    it('should parse and throw API errors with details', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({
          error: {
            code: 'FINGERPRINT_MISMATCH',
            message: 'Public key does not match fingerprint',
            details: { expected: 'abc', got: 'xyz' }
          }
        })
      });
      global.fetch = fetchMock;

      await expect(client.post('/challenge', {})).rejects.toMatchObject({
        code: 'FINGERPRINT_MISMATCH',
        message: 'Public key does not match fingerprint',
        details: { expected: 'abc', got: 'xyz' }
      });
    });

    it('should handle network errors', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockRejectedValue(
        new Error('Network request failed')
      );
      global.fetch = fetchMock;

      await expect(client.post('/challenge', {})).rejects.toThrow(
        /Network request failed/
      );
    });

    it('should handle timeout errors', async () => {
      const client = new HttpClient({ ...config, timeout: 100 });
      const fetchMock = vi.fn().mockImplementation(() =>
        new Promise((resolve, reject) => {
          setTimeout(() => {
            // Simulate AbortError
            const abortError = new Error('The operation was aborted');
            abortError.name = 'AbortError';
            reject(abortError);
          }, 200);
        })
      );
      global.fetch = fetchMock;

      await expect(client.post('/challenge', {})).rejects.toThrow(/timeout/i);
    });
  });

  describe('GET Requests', () => {
    it('should make GET requests without body', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: 'success' })
      });
      global.fetch = fetchMock;

      await client.get('/info');

      expect(fetchMock).toHaveBeenCalledWith(
        'https://sigil.example.com/info',
        expect.objectContaining({
          method: 'GET'
        })
      );
    });

    it('should include query parameters in GET', async () => {
      const client = new HttpClient(config);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: 'success' })
      });
      global.fetch = fetchMock;

      await client.get('/v1/auth/challenge/123/status');

      expect(fetchMock).toHaveBeenCalledWith(
        'https://sigil.example.com/v1/auth/challenge/123/status',
        expect.any(Object)
      );
    });
  });
});
