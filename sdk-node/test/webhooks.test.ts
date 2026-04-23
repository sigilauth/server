import { describe, it, expect } from 'vitest';
import { WebhookVerifier } from '../src/webhooks.js';
import { createHmac } from 'crypto';

describe('Webhook Verifier', () => {
  const secret = 'whsec_test_' + 'a'.repeat(40);
  const verifier = new WebhookVerifier(secret);

  describe('verify', () => {
    it('should verify valid webhook signature', () => {
      const body = JSON.stringify({
        type: 'challenge.verified',
        challenge_id: '550e8400-e29b-41d4-a716-446655440000',
        fingerprint: 'a'.repeat(64)
      });
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const hmac = createHmac('sha256', secret);
      hmac.update(timestamp + '.' + body);
      const signature = 'v1=' + hmac.digest('hex');

      const result = verifier.verify(body, signature, timestamp);

      expect(result).toBe(true);
    });

    it('should reject webhook with invalid signature', () => {
      const body = JSON.stringify({ type: 'challenge.verified' });
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const invalidSignature = 'v1=' + 'a'.repeat(64);

      const result = verifier.verify(body, invalidSignature, timestamp);

      expect(result).toBe(false);
    });

    it('should reject webhook with timestamp too old', () => {
      const body = JSON.stringify({ type: 'challenge.verified' });
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString();  // 10 minutes ago

      const hmac = createHmac('sha256', secret);
      hmac.update(oldTimestamp + '.' + body);
      const signature = 'v1=' + hmac.digest('hex');

      const result = verifier.verify(body, signature, oldTimestamp);

      expect(result).toBe(false);
    });

    it('should reject webhook with future timestamp', () => {
      const body = JSON.stringify({ type: 'challenge.verified' });
      const futureTimestamp = (Math.floor(Date.now() / 1000) + 600).toString();  // 10 minutes future

      const hmac = createHmac('sha256', secret);
      hmac.update(futureTimestamp + '.' + body);
      const signature = 'v1=' + hmac.digest('hex');

      const result = verifier.verify(body, signature, futureTimestamp);

      expect(result).toBe(false);
    });

    it('should use custom tolerance window', () => {
      const verifier = new WebhookVerifier(secret, { toleranceSeconds: 600 });
      const body = JSON.stringify({ type: 'challenge.verified' });
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 500).toString();  // 8.3 minutes ago

      const hmac = createHmac('sha256', secret);
      hmac.update(oldTimestamp + '.' + body);
      const signature = 'v1=' + hmac.digest('hex');

      const result = verifier.verify(body, signature, oldTimestamp);

      expect(result).toBe(true);  // Should pass with 600s tolerance
    });

    it('should extract signature from v1= prefix', () => {
      const body = JSON.stringify({ type: 'challenge.verified' });
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const hmac = createHmac('sha256', secret);
      hmac.update(timestamp + '.' + body);
      const expectedSig = hmac.digest('hex');

      // Test with prefix
      const withPrefix = verifier.verify(body, 'v1=' + expectedSig, timestamp);
      expect(withPrefix).toBe(true);

      // Test without prefix (should also work)
      const withoutPrefix = verifier.verify(body, expectedSig, timestamp);
      expect(withoutPrefix).toBe(true);
    });
  });

  describe('verifyAndParse', () => {
    it('should verify and parse valid webhook', () => {
      const payload = {
        type: 'challenge.verified',
        challenge_id: '550e8400-e29b-41d4-a716-446655440000',
        fingerprint: 'a'.repeat(64)
      };
      const body = JSON.stringify(payload);
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const hmac = createHmac('sha256', secret);
      hmac.update(timestamp + '.' + body);
      const signature = 'v1=' + hmac.digest('hex');

      const result = verifier.verifyAndParse(body, signature, timestamp);

      expect(result).toEqual(payload);
    });

    it('should throw on invalid signature', () => {
      const body = JSON.stringify({ type: 'challenge.verified' });
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const invalidSignature = 'v1=' + 'a'.repeat(64);

      expect(() => {
        verifier.verifyAndParse(body, invalidSignature, timestamp);
      }).toThrow(/Invalid webhook signature/i);
    });

    it('should throw on expired timestamp', () => {
      const body = JSON.stringify({ type: 'challenge.verified' });
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString();

      const hmac = createHmac('sha256', secret);
      hmac.update(oldTimestamp + '.' + body);
      const signature = 'v1=' + hmac.digest('hex');

      expect(() => {
        verifier.verifyAndParse(body, signature, oldTimestamp);
      }).toThrow(/Webhook timestamp outside tolerance/i);
    });

    it('should throw on invalid JSON', () => {
      const body = 'not json';
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const hmac = createHmac('sha256', secret);
      hmac.update(timestamp + '.' + body);
      const signature = 'v1=' + hmac.digest('hex');

      expect(() => {
        verifier.verifyAndParse(body, signature, timestamp);
      }).toThrow(/Failed to parse webhook/i);
    });
  });
});
