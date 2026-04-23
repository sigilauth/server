import type { ValidatedConfig } from './config.js';
import {
  SigilAuthError,
  SigilAuthNetworkError,
  SigilAuthTimeoutError,
  shouldRetry
} from './errors.js';

export class HttpClient {
  constructor(private readonly config: ValidatedConfig) {}

  async get<T = unknown>(path: string): Promise<T> {
    return this.request('GET', path);
  }

  async post<T = unknown>(path: string, body: unknown): Promise<T> {
    return this.request('POST', path, body);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      if (attempt > 0) {
        const delay = this.config.retryDelays[attempt - 1] ?? 400;
        await this.sleep(delay);
      }

      try {
        return await this.executeRequest<T>(method, path, body);
      } catch (error) {
        lastError = error as Error;

        if (!shouldRetry(error)) {
          throw error;
        }

        // Last attempt?
        if (attempt === this.config.maxRetries) {
          throw error;
        }
      }
    }

    throw lastError ?? new Error('Request failed');
  }

  private async executeRequest<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = `${this.config.serviceUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.config.apiKey}`
    };

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const error = errorData.error || {};

        throw new SigilAuthError(
          error.code || 'UNKNOWN_ERROR',
          error.message || `HTTP ${response.status}`,
          error.details,
          response.status
        );
      }

      return await response.json() as T;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof SigilAuthError) {
        throw error;
      }

      if ((error as Error).name === 'AbortError') {
        throw new SigilAuthTimeoutError(
          `Request timeout after ${this.config.timeout}ms`
        );
      }

      throw new SigilAuthNetworkError(
        'Network request failed',
        error as Error
      );
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
