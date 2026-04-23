import { validateConfig, type SigilAuthConfig, type ValidatedConfig } from './config.js';

export class SigilAuth {
  public readonly config: ValidatedConfig;

  constructor(config: SigilAuthConfig) {
    this.config = validateConfig(config);
  }
}

export type { SigilAuthConfig, ValidatedConfig };
export { validateConfig };
