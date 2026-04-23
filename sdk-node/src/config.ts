export interface SigilAuthConfig {
  serviceUrl: string;
  apiKey?: string;
  rejectUnauthorized?: boolean;
  certFingerprints?: string[];
  maxRetries?: number;
  retryDelays?: number[];
  timeout?: number;
}

export interface ValidatedConfig {
  serviceUrl: string;
  apiKey: string;
  rejectUnauthorized: true;
  certFingerprints?: string[];
  maxRetries: number;
  retryDelays: number[];
  timeout: number;
}

const API_KEY_PATTERN = /^sgk_(live|test)_[a-f0-9]{64}$/;
const DEFAULT_RETRY_DELAYS = [100, 200, 400];
const DEFAULT_TIMEOUT = 10000;
const MAX_RETRIES_LIMIT = 10;
const MIN_TIMEOUT = 1000;

export function validateConfig(config: SigilAuthConfig): ValidatedConfig {
  if (config.apiKey !== undefined) {
    throw new Error(
      'API key must be loaded from environment variable SIGIL_API_KEY, not passed directly. ' +
      'Hardcoded secrets are a security violation.'
    );
  }

  const apiKey = process.env.SIGIL_API_KEY;
  if (!apiKey) {
    throw new Error(
      'SIGIL_API_KEY environment variable not set. ' +
      'Load your API key from environment, never hardcode it.'
    );
  }

  if (!API_KEY_PATTERN.test(apiKey)) {
    throw new Error(
      'Invalid API key format. Expected: sgk_live_<64-hex> or sgk_test_<64-hex>'
    );
  }

  if (config.rejectUnauthorized === false) {
    throw new Error(
      'TLS verification cannot be disabled. This is a security requirement. ' +
      'Use certFingerprints for certificate pinning if needed.'
    );
  }

  let url: URL;
  try {
    url = new URL(config.serviceUrl);
  } catch (error) {
    throw new Error(
      `Invalid service URL: ${config.serviceUrl}`
    );
  }

  if (url.protocol !== 'https:') {
    throw new Error(
      `Service URL must use HTTPS. Got: ${url.protocol}//`
    );
  }

  const maxRetries = config.maxRetries ?? DEFAULT_RETRY_DELAYS.length;
  if (maxRetries > MAX_RETRIES_LIMIT) {
    throw new Error(
      `maxRetries cannot exceed ${MAX_RETRIES_LIMIT}. Got: ${maxRetries}`
    );
  }

  const retryDelays = config.retryDelays ?? DEFAULT_RETRY_DELAYS;

  const timeout = config.timeout ?? DEFAULT_TIMEOUT;
  if (timeout < MIN_TIMEOUT) {
    throw new Error(
      `timeout must be at least ${MIN_TIMEOUT}ms. Got: ${timeout}ms`
    );
  }

  return {
    serviceUrl: config.serviceUrl,
    apiKey,
    rejectUnauthorized: true,
    certFingerprints: config.certFingerprints,
    maxRetries,
    retryDelays,
    timeout
  };
}
