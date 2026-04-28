import { validateConfig, type SigilAuthConfig, type ValidatedConfig } from './config.js';
import { HttpClient } from './http-client.js';
import { AuthClient } from './auth-client.js';
import { MPAClient } from './mpa-client.js';
import { WebhookVerifier } from './webhooks.js';

export class SigilAuth {
  public readonly config: ValidatedConfig;
  public readonly auth: AuthClient;
  public readonly mpa: MPAClient;
  public readonly webhooks: WebhookVerifier;
  private readonly http: HttpClient;

  constructor(config: SigilAuthConfig, webhookSecret?: string) {
    this.config = validateConfig(config);
    this.http = new HttpClient(this.config);
    this.auth = new AuthClient(this.http);
    this.mpa = new MPAClient(this.http);
    this.webhooks = new WebhookVerifier(webhookSecret ?? '');
  }
}

export type { SigilAuthConfig, ValidatedConfig };
export { validateConfig, WebhookVerifier };
