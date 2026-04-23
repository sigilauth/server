import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SigilAuth } from '../src/index.js';

describe('SDK Configuration Security', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.SIGIL_API_KEY;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('API Key Validation', () => {
    it('should reject hardcoded API key in constructor', () => {
      expect(() => {
        new SigilAuth({
          serviceUrl: 'https://sigil.example.com',
          apiKey: 'sgk_live_abc123'  // Violation #5: Hardcoded secret
        });
      }).toThrow(/API key must be loaded from environment variable/i);
    });

    it('should accept API key from environment variable', () => {
      process.env.SIGIL_API_KEY = 'sgk_live_' + 'a'.repeat(64);

      expect(() => {
        new SigilAuth({
          serviceUrl: 'https://sigil.example.com'
        });
      }).not.toThrow();
    });

    it('should throw if no API key in environment', () => {
      expect(() => {
        new SigilAuth({
          serviceUrl: 'https://sigil.example.com'
        });
      }).toThrow(/SIGIL_API_KEY environment variable not set/i);
    });

    it('should validate API key format (sgk_live_ or sgk_test_)', () => {
      process.env.SIGIL_API_KEY = 'invalid_format';

      expect(() => {
        new SigilAuth({
          serviceUrl: 'https://sigil.example.com'
        });
      }).toThrow(/Invalid API key format/i);
    });

    it('should accept test API keys', () => {
      process.env.SIGIL_API_KEY = 'sgk_test_' + 'a'.repeat(64);

      expect(() => {
        new SigilAuth({
          serviceUrl: 'https://sigil.example.com'
        });
      }).not.toThrow();
    });
  });

  describe('TLS Verification', () => {
    beforeEach(() => {
      process.env.SIGIL_API_KEY = 'sgk_live_' + 'a'.repeat(64);
    });

    it('should enforce TLS verification by default', () => {
      const client = new SigilAuth({
        serviceUrl: 'https://sigil.example.com'
      });

      expect(client.config.rejectUnauthorized).toBe(true);
    });

    it('should reject attempts to disable TLS verification', () => {
      expect(() => {
        new SigilAuth({
          serviceUrl: 'https://sigil.example.com',
          rejectUnauthorized: false  // Security violation
        });
      }).toThrow(/TLS verification cannot be disabled/i);
    });

    it('should allow certificate pinning configuration', () => {
      const client = new SigilAuth({
        serviceUrl: 'https://sigil.example.com',
        certFingerprints: ['sha256/abc123...']
      });

      expect(client.config.certFingerprints).toEqual(['sha256/abc123...']);
    });
  });

  describe('Service URL Validation', () => {
    beforeEach(() => {
      process.env.SIGIL_API_KEY = 'sgk_live_' + 'a'.repeat(64);
    });

    it('should require HTTPS URLs', () => {
      expect(() => {
        new SigilAuth({
          serviceUrl: 'http://sigil.example.com'  // HTTP not HTTPS
        });
      }).toThrow(/Service URL must use HTTPS/i);
    });

    it('should accept valid HTTPS URLs', () => {
      expect(() => {
        new SigilAuth({
          serviceUrl: 'https://sigil.example.com'
        });
      }).not.toThrow();
    });

    it('should reject malformed URLs', () => {
      expect(() => {
        new SigilAuth({
          serviceUrl: 'not-a-url'
        });
      }).toThrow(/Invalid service URL/i);
    });
  });

  describe('Retry Configuration', () => {
    beforeEach(() => {
      process.env.SIGIL_API_KEY = 'sgk_live_' + 'a'.repeat(64);
    });

    it('should use default retry policy (3 retries, exp backoff)', () => {
      const client = new SigilAuth({
        serviceUrl: 'https://sigil.example.com'
      });

      expect(client.config.maxRetries).toBe(3);
      expect(client.config.retryDelays).toEqual([100, 200, 400]);
    });

    it('should allow custom retry configuration', () => {
      const client = new SigilAuth({
        serviceUrl: 'https://sigil.example.com',
        maxRetries: 5,
        retryDelays: [50, 100, 200, 400, 800]
      });

      expect(client.config.maxRetries).toBe(5);
      expect(client.config.retryDelays).toEqual([50, 100, 200, 400, 800]);
    });

    it('should enforce max retry limit', () => {
      expect(() => {
        new SigilAuth({
          serviceUrl: 'https://sigil.example.com',
          maxRetries: 100  // Excessive retries
        });
      }).toThrow(/maxRetries cannot exceed 10/i);
    });
  });

  describe('Timeout Configuration', () => {
    beforeEach(() => {
      process.env.SIGIL_API_KEY = 'sgk_live_' + 'a'.repeat(64);
    });

    it('should use default timeout (10 seconds)', () => {
      const client = new SigilAuth({
        serviceUrl: 'https://sigil.example.com'
      });

      expect(client.config.timeout).toBe(10000);
    });

    it('should allow custom timeout', () => {
      const client = new SigilAuth({
        serviceUrl: 'https://sigil.example.com',
        timeout: 5000
      });

      expect(client.config.timeout).toBe(5000);
    });

    it('should enforce minimum timeout (1 second)', () => {
      expect(() => {
        new SigilAuth({
          serviceUrl: 'https://sigil.example.com',
          timeout: 500  // Too short
        });
      }).toThrow(/timeout must be at least 1000ms/i);
    });
  });
});
