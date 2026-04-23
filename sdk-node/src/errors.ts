export class SigilAuthError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>,
    public readonly statusCode?: number
  ) {
    super(message);
    this.name = 'SigilAuthError';
  }
}

export class SigilAuthNetworkError extends Error {
  constructor(message: string, public readonly cause?: Error) {
    super(message);
    this.name = 'SigilAuthNetworkError';
  }
}

export class SigilAuthTimeoutError extends Error {
  constructor(message: string = 'Request timeout exceeded') {
    super(message);
    this.name = 'SigilAuthTimeoutError';
  }
}

export function isRetryableStatusCode(status: number): boolean {
  return status === 429 || status >= 500;
}

export function shouldRetry(error: unknown): boolean {
  if (error instanceof SigilAuthError) {
    return isRetryableStatusCode(error.statusCode ?? 0);
  }
  if (error instanceof SigilAuthNetworkError) {
    return true;  // Network errors are transient
  }
  if (error instanceof SigilAuthTimeoutError) {
    return true;  // Timeouts can be retried
  }
  return false;
}
