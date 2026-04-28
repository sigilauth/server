import { createHmac, timingSafeEqual } from 'crypto';

const DEFAULT_TOLERANCE_SECONDS = 300;  // 5 minutes per Knox spec

export interface WebhookVerifierOptions {
  toleranceSeconds?: number;
}

export class WebhookVerifier {
  private readonly toleranceSeconds: number;

  constructor(
    private readonly secret: string,
    options?: WebhookVerifierOptions
  ) {
    this.toleranceSeconds = options?.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  }

  verify(body: string, signature: string, timestamp: string): boolean {
    // Check timestamp is within tolerance window
    const timestampNum = parseInt(timestamp, 10);
    if (isNaN(timestampNum)) {
      return false;
    }

    const now = Math.floor(Date.now() / 1000);
    const diff = Math.abs(now - timestampNum);

    if (diff > this.toleranceSeconds) {
      return false;
    }

    // Extract signature (remove v1= prefix if present)
    const providedSig = signature.startsWith('v1=')
      ? signature.substring(3)
      : signature;

    // Compute expected signature
    const payload = `${timestamp}.${body}`;
    const hmac = createHmac('sha256', this.secret);
    hmac.update(payload);
    const expectedSig = hmac.digest('hex');

    // Constant-time comparison to prevent timing attacks
    if (providedSig.length !== expectedSig.length) {
      return false;
    }

    try {
      return timingSafeEqual(
        Buffer.from(providedSig, 'hex'),
        Buffer.from(expectedSig, 'hex')
      );
    } catch {
      return false;
    }
  }

  verifyAndParse<T = unknown>(
    body: string,
    signature: string,
    timestamp: string
  ): T {
    if (!this.verify(body, signature, timestamp)) {
      const timestampNum = parseInt(timestamp, 10);
      const now = Math.floor(Date.now() / 1000);
      const diff = Math.abs(now - timestampNum);

      if (diff > this.toleranceSeconds) {
        throw new Error(
          `Webhook timestamp outside tolerance window. ` +
          `Timestamp: ${timestamp}, Now: ${now}, Diff: ${diff}s, Tolerance: ${this.toleranceSeconds}s`
        );
      }

      throw new Error('Invalid webhook signature');
    }

    try {
      return JSON.parse(body) as T;
    } catch (error) {
      throw new Error(
        `Failed to parse webhook body as JSON: ${(error as Error).message}`
      );
    }
  }
}
