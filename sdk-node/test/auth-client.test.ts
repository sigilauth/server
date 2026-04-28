import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SigilAuth } from '../src/index.js';
import type { components } from '../src/generated/api-types.js';

type ChallengeRequest = components['schemas']['ChallengeRequest'];
type ChallengeCreated = components['schemas']['ChallengeCreated'];
type ChallengeStatus = components['schemas']['ChallengeStatus'];

describe('Auth Client', () => {
  let client: SigilAuth;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    process.env.SIGIL_API_KEY = 'sgk_test_' + 'a'.repeat(64);

    fetchMock = vi.fn();
    global.fetch = fetchMock;

    client = new SigilAuth({
      serviceUrl: 'https://sigil.example.com'
    });
  });

  describe('createChallenge', () => {
    it('should create challenge and return metadata', async () => {
      const request: ChallengeRequest = {
        fingerprint: 'a'.repeat(64),
        device_public_key: 'AgABAgMEBQYH...',
        action: {
          type: 'step_up',
          description: 'Add WebAuthn key',
          params: { key_name: 'YubiKey' }
        }
      };

      const response: ChallengeCreated = {
        challenge_id: '550e8400-e29b-41d4-a716-446655440000',
        fingerprint: 'a'.repeat(64),
        pictogram: ['apple', 'banana', 'plane', 'car', 'dog'],
        pictogram_speakable: 'apple banana plane car dog',
        expires_at: '2026-04-23T10:05:00Z'
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => response
      });

      const result = await client.auth.createChallenge(request);

      expect(fetchMock).toHaveBeenCalledWith(
        'https://sigil.example.com/challenge',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(request)
        })
      );
      expect(result).toEqual(response);
    });

    it('should validate fingerprint format', async () => {
      await expect(
        client.auth.createChallenge({
          fingerprint: 'invalid',  // Not 64 hex chars
          device_public_key: 'AgABAgMEBQYH...',
          action: { type: 'step_up', description: 'test' }
        })
      ).rejects.toThrow(/Invalid fingerprint format/i);
    });

    it('should handle FINGERPRINT_MISMATCH error', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({
          error: {
            code: 'FINGERPRINT_MISMATCH',
            message: 'Public key does not match fingerprint'
          }
        })
      });

      await expect(
        client.auth.createChallenge({
          fingerprint: 'a'.repeat(64),
          device_public_key: 'AgABAgMEBQYH...',
          action: { type: 'step_up', description: 'test' }
        })
      ).rejects.toMatchObject({
        code: 'FINGERPRINT_MISMATCH'
      });
    });
  });

  describe('getStatus', () => {
    it('should poll challenge status', async () => {
      const challengeId = '550e8400-e29b-41d4-a716-446655440000';
      const response: ChallengeStatus = {
        challenge_id: challengeId,
        status: 'pending'
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => response
      });

      const result = await client.auth.getStatus(challengeId);

      expect(fetchMock).toHaveBeenCalledWith(
        `https://sigil.example.com/v1/auth/challenge/${challengeId}/status`,
        expect.objectContaining({
          method: 'GET'
        })
      );
      expect(result).toEqual(response);
    });

    it('should return verified status with metadata', async () => {
      const challengeId = '550e8400-e29b-41d4-a716-446655440000';
      const response: ChallengeStatus = {
        challenge_id: challengeId,
        status: 'verified',
        fingerprint: 'a'.repeat(64),
        pictogram: ['apple', 'banana', 'plane', 'car', 'dog'],
        pictogram_speakable: 'apple banana plane car dog',
        decision: 'approved',
        verified_at: '2026-04-23T10:02:30Z'
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => response
      });

      const result = await client.auth.getStatus(challengeId);

      expect(result.status).toBe('verified');
      expect(result.decision).toBe('approved');
      expect(result.pictogram).toEqual(['apple', 'banana', 'plane', 'car', 'dog']);
    });

    it('should handle 404 for expired challenges', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({
          error: {
            code: 'CHALLENGE_NOT_FOUND',
            message: 'Challenge not found or expired'
          }
        })
      });

      await expect(
        client.auth.getStatus('550e8400-e29b-41d4-a716-446655440000')
      ).rejects.toMatchObject({
        code: 'CHALLENGE_NOT_FOUND',
        statusCode: 404
      });
    });
  });

  describe('awaitResult', () => {
    it('should poll until verified', async () => {
      const challengeId = '550e8400-e29b-41d4-a716-446655440000';

      fetchMock
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ challenge_id: challengeId, status: 'pending' })
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ challenge_id: challengeId, status: 'pending' })
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            challenge_id: challengeId,
            status: 'verified',
            fingerprint: 'a'.repeat(64),
            decision: 'approved',
            verified_at: '2026-04-23T10:02:30Z'
          })
        });

      const result = await client.auth.awaitResult(challengeId, {
        pollInterval: 100,
        timeout: 5000
      });

      expect(result.status).toBe('verified');
      expect(fetchMock).toHaveBeenCalledTimes(3);
    });

    it('should timeout if challenge not resolved', async () => {
      const challengeId = '550e8400-e29b-41d4-a716-446655440000';

      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ challenge_id: challengeId, status: 'pending' })
      });

      await expect(
        client.auth.awaitResult(challengeId, {
          pollInterval: 100,
          timeout: 300  // Short timeout for test speed
        })
      ).rejects.toThrow(/Challenge polling timeout/i);

      // Should have polled multiple times
      expect(fetchMock.mock.calls.length).toBeGreaterThan(1);
    });

    it('should stop polling on rejected status', async () => {
      const challengeId = '550e8400-e29b-41d4-a716-446655440000';

      fetchMock
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ challenge_id: challengeId, status: 'pending' })
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            challenge_id: challengeId,
            status: 'rejected',
            decision: 'rejected'
          })
        });

      const result = await client.auth.awaitResult(challengeId, {
        pollInterval: 100,
        timeout: 5000
      });

      expect(result.status).toBe('rejected');
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('should stop polling on expired status', async () => {
      const challengeId = '550e8400-e29b-41d4-a716-446655440000';

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          challenge_id: challengeId,
          status: 'expired'
        })
      });

      const result = await client.auth.awaitResult(challengeId, {
        pollInterval: 100,
        timeout: 5000
      });

      expect(result.status).toBe('expired');
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('should use default poll interval and timeout', async () => {
      const challengeId = '550e8400-e29b-41d4-a716-446655440000';

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          challenge_id: challengeId,
          status: 'verified',
          decision: 'approved'
        })
      });

      const result = await client.auth.awaitResult(challengeId);

      expect(result.status).toBe('verified');
    });
  });
});
