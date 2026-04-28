import { HttpClient } from './http-client.js';
import type { components } from './generated/api-types.js';

type MPARequest = components['schemas']['MPARequest'];
type MPACreated = components['schemas']['MPACreated'];
type MPAStatus = components['schemas']['MPAStatus'];

const MIN_EXPIRES_SECONDS = 60;
const MAX_EXPIRES_SECONDS = 900;
const DEFAULT_POLL_INTERVAL = 3000;  // 3 seconds (MPA is human-in-loop)
const DEFAULT_POLL_TIMEOUT = 180000;  // 180 seconds (3 minutes)

export interface MPAAwaitOptions {
  pollInterval?: number;
  timeout?: number;
}

export class MPAClient {
  constructor(private readonly http: HttpClient) {}

  async request(request: MPARequest): Promise<MPACreated> {
    this.validateRequest(request);
    return this.http.post<MPACreated>('/mpa/request', request);
  }

  async getStatus(requestId: string): Promise<MPAStatus> {
    return this.http.get<MPAStatus>(`/mpa/status/${requestId}`);
  }

  async awaitResult(
    requestId: string,
    options?: MPAAwaitOptions
  ): Promise<MPAStatus> {
    const pollInterval = options?.pollInterval ?? DEFAULT_POLL_INTERVAL;
    const timeout = options?.timeout ?? DEFAULT_POLL_TIMEOUT;
    const startTime = Date.now();

    while (true) {
      const status = await this.getStatus(requestId);

      if (this.isTerminalStatus(status.status)) {
        return status;
      }

      if (Date.now() - startTime >= timeout) {
        throw new Error(
          `MPA polling timeout after ${timeout}ms. ` +
          `Status: ${status.status}, ` +
          `Progress: ${status.groups_satisfied?.length ?? 0}/${status.groups_required}`
        );
      }

      await this.sleep(pollInterval);
    }
  }

  private validateRequest(request: MPARequest): void {
    if (request.required > request.groups.length) {
      throw new Error(
        `Invalid MPA request: required (${request.required}) ` +
        `cannot exceed number of groups (${request.groups.length})`
      );
    }

    if (request.required < 1) {
      throw new Error(
        `Invalid MPA request: required must be at least 1, got ${request.required}`
      );
    }

    const expiresIn = request.expires_in_seconds ?? 300;
    if (expiresIn < MIN_EXPIRES_SECONDS || expiresIn > MAX_EXPIRES_SECONDS) {
      throw new Error(
        `Invalid expires_in_seconds: must be between ${MIN_EXPIRES_SECONDS} ` +
        `and ${MAX_EXPIRES_SECONDS}, got ${expiresIn}`
      );
    }
  }

  private isTerminalStatus(status: string): boolean {
    return status === 'approved' || status === 'rejected' || status === 'timeout';
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
