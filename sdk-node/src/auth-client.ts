import { HttpClient } from './http-client.js';
import type { components } from './generated/api-types.js';

type ChallengeRequest = components['schemas']['ChallengeRequest'];
type ChallengeCreated = components['schemas']['ChallengeCreated'];
type ChallengeStatus = components['schemas']['ChallengeStatus'];

const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const DEFAULT_POLL_INTERVAL = 2000;  // 2 seconds
const DEFAULT_POLL_TIMEOUT = 60000;  // 60 seconds

export interface AwaitOptions {
  pollInterval?: number;
  timeout?: number;
}

export class AuthClient {
  constructor(private readonly http: HttpClient) {}

  async createChallenge(request: ChallengeRequest): Promise<ChallengeCreated> {
    this.validateFingerprint(request.fingerprint);
    return this.http.post<ChallengeCreated>('/challenge', request);
  }

  async getStatus(challengeId: string): Promise<ChallengeStatus> {
    return this.http.get<ChallengeStatus>(
      `/v1/auth/challenge/${challengeId}/status`
    );
  }

  async awaitResult(
    challengeId: string,
    options?: AwaitOptions
  ): Promise<ChallengeStatus> {
    const pollInterval = options?.pollInterval ?? DEFAULT_POLL_INTERVAL;
    const timeout = options?.timeout ?? DEFAULT_POLL_TIMEOUT;
    const startTime = Date.now();

    while (true) {
      const status = await this.getStatus(challengeId);

      if (this.isTerminalStatus(status.status)) {
        return status;
      }

      if (Date.now() - startTime >= timeout) {
        throw new Error(
          `Challenge polling timeout after ${timeout}ms. ` +
          `Status: ${status.status}`
        );
      }

      await this.sleep(pollInterval);
    }
  }

  private validateFingerprint(fingerprint: string): void {
    if (!FINGERPRINT_PATTERN.test(fingerprint)) {
      throw new Error(
        `Invalid fingerprint format. Expected 64 hex characters, got: ${fingerprint}`
      );
    }
  }

  private isTerminalStatus(status: string): boolean {
    return status === 'verified' || status === 'rejected' || status === 'expired';
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
