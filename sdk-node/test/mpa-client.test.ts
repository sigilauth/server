import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SigilAuth } from '../src/index.js';
import type { components } from '../src/generated/api-types.js';

type MPARequest = components['schemas']['MPARequest'];
type MPACreated = components['schemas']['MPACreated'];
type MPAStatus = components['schemas']['MPAStatus'];

describe('MPA Client', () => {
  let client: SigilAuth;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    process.env.SIGIL_API_KEY = 'sgk_test_' + 'a'.repeat(64);
    fetchMock = vi.fn();
    global.fetch = fetchMock;
    client = new SigilAuth({ serviceUrl: 'https://sigil.example.com' });
  });

  describe('request', () => {
    it('should create MPA request', async () => {
      const request: MPARequest = {
        request_id: 'mpa_xyz789',
        action: {
          type: 'engine:cold-boot',
          description: 'Cold boot engine ENG-001',
          params: { engine_id: 'eng_001' }
        },
        required: 2,
        groups: [
          { members: [{ fingerprint: 'a'.repeat(64), device_public_key: 'AgABAgMEBQYH...' }] },
          { members: [{ fingerprint: 'b'.repeat(64), device_public_key: 'AgABAgMEBQYH...' }] }
        ],
        reject_policy: 'continue',
        expires_in_seconds: 300
      };

      const response: MPACreated = {
        request_id: 'mpa_xyz789',
        status: 'pending',
        groups_required: 2,
        groups_total: 2,
        challenges_sent: 2,
        expires_at: '2026-04-23T10:10:00Z'
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => response
      });

      const result = await client.mpa.request(request);

      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(result).toEqual(response);
    });

    it('should validate required groups count', async () => {
      await expect(
        client.mpa.request({
          request_id: 'mpa_test',
          action: { type: 'test', description: 'test' },
          required: 3,
          groups: [{ members: [{ fingerprint: 'a'.repeat(64), device_public_key: 'test' }] }],
          expires_in_seconds: 300
        })
      ).rejects.toThrow(/required.*cannot exceed.*groups/i);
    });

    it('should validate expires_in_seconds range', async () => {
      await expect(
        client.mpa.request({
          request_id: 'mpa_test',
          action: { type: 'test', description: 'test' },
          required: 1,
          groups: [{ members: [{ fingerprint: 'a'.repeat(64), device_public_key: 'test' }] }],
          expires_in_seconds: 30
        })
      ).rejects.toThrow(/expires_in_seconds.*60.*900/i);
    });
  });

  describe('getStatus', () => {
    it('should poll MPA status', async () => {
      const requestId = 'mpa_xyz789';
      const response: MPAStatus = {
        request_id: requestId,
        status: 'pending',
        groups_satisfied: [0],
        groups_required: 2,
        groups_total: 2,
        expires_at: '2026-04-23T10:10:00Z'
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => response
      });

      const result = await client.mpa.getStatus(requestId);
      expect(result).toEqual(response);
    });

    it('should return approved status when quorum reached', async () => {
      const response: MPAStatus = {
        request_id: 'mpa_xyz789',
        status: 'approved',
        groups_satisfied: [0, 1],
        groups_required: 2,
        groups_total: 2
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => response
      });

      const result = await client.mpa.getStatus('mpa_xyz789');
      expect(result.status).toBe('approved');
      expect(result.groups_satisfied).toHaveLength(2);
    });
  });

  describe('awaitResult', () => {
    it('should poll until approved', async () => {
      const requestId = 'mpa_xyz789';

      fetchMock
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            request_id: requestId,
            status: 'pending',
            groups_satisfied: [],
            groups_required: 2,
            groups_total: 2
          })
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            request_id: requestId,
            status: 'pending',
            groups_satisfied: [0],
            groups_required: 2,
            groups_total: 2
          })
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            request_id: requestId,
            status: 'approved',
            groups_satisfied: [0, 1],
            groups_required: 2,
            groups_total: 2
          })
        });

      const result = await client.mpa.awaitResult(requestId, { pollInterval: 100, timeout: 5000 });
      expect(result.status).toBe('approved');
      expect(fetchMock).toHaveBeenCalledTimes(3);
    });

    it('should timeout if MPA not resolved', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          request_id: 'mpa_xyz789',
          status: 'pending',
          groups_satisfied: [],
          groups_required: 2,
          groups_total: 2
        })
      });

      await expect(
        client.mpa.awaitResult('mpa_xyz789', { pollInterval: 100, timeout: 300 })
      ).rejects.toThrow(/MPA polling timeout/i);
    });

    it('should stop polling on rejected status', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          request_id: 'mpa_xyz789',
          status: 'rejected',
          groups_satisfied: [],
          groups_required: 2,
          groups_total: 2
        })
      });

      const result = await client.mpa.awaitResult('mpa_xyz789', { pollInterval: 100, timeout: 5000 });
      expect(result.status).toBe('rejected');
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('should stop polling on timeout status', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          request_id: 'mpa_xyz789',
          status: 'timeout',
          groups_satisfied: [0],
          groups_required: 2,
          groups_total: 2
        })
      });

      const result = await client.mpa.awaitResult('mpa_xyz789', { pollInterval: 100, timeout: 5000 });
      expect(result.status).toBe('timeout');
    });
  });
});
