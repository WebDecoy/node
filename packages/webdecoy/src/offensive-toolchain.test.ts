import { createHash, createHmac, webcrypto } from 'crypto';
import { createOffensiveToolchainEvidence } from './offensive-toolchain';
import { WebDecoy } from './sdk';

const correlationSecret = 'test-correlation-secret-at-least-32-characters';

beforeAll(() => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
});

describe('createOffensiveToolchainEvidence', () => {
  it('returns only bounded generic families and keyed digests', async () => {
    const evidence = await createOffensiveToolchainEvidence({
      sensor: 'mcp-proxy',
      runId: 'customer-secret-run-id',
      correlationSecret,
      invocations: [
        { tool: 'nmap_scan', redactedArgumentCount: 2 },
        { tool: 'nuclei_scan', redactedArgumentCount: 1 },
        { tool: 'private_custom_tool', redactedArgumentCount: 99 },
      ],
    });
    expect(evidence.framework_evidence).toBeUndefined();
    expect(evidence.offensive_toolchain).toMatchObject({
      schema_version: 1,
      registry_revision: 1,
      plane: 'model_api',
      sensor: 'mcp-proxy',
      tool_families: ['network_reconnaissance', 'vulnerability_scanning'],
      invocation_count: 2,
      redacted_argument_count: 3,
      dropped_tool_count: 1,
    });
    expect(evidence.offensive_toolchain.run_correlation_id).toBe(
      createHmac('sha256', correlationSecret).update('customer-secret-run-id').digest('hex')
    );
    expect(evidence.offensive_toolchain.family_set_sha256).toBe(
      createHash('sha256').update('network_reconnaissance\nvulnerability_scanning').digest('hex')
    );
    const wire = JSON.stringify(evidence);
    for (const forbidden of [
      'customer-secret-run-id',
      correlationSecret,
      'private_custom_tool',
      'arguments',
      'targets',
    ]) {
      expect(wire).not.toContain(forbidden);
    }
  });

  it('adds HexStrike identity only when explicitly requested', async () => {
    const evidence = await createOffensiveToolchainEvidence({
      sensor: 'hexstrike-sidecar',
      runId: 'run-1',
      correlationSecret,
      orchestrator: 'hexstrike_ai',
      invocations: [{ tool: 'nmap_scan' }, { tool: 'metasploit_run' }],
    });
    expect(evidence.framework_evidence).toMatchObject({
      schema_version: 1,
      registry_revision: 5,
      framework: 'hexstrike_ai',
      plane: 'model_api',
      evidence: [{ family_id: 'orchestrator_identity', count: 1 }],
    });
    expect(evidence.framework_evidence?.evidence[0].sha256).toBe(
      '18ff7e9eabdbb58d0a3b4330674499a234b0d49cd3f3b3efbe16713a8c5d5e79'
    );
    expect(evidence.framework_evidence?.observation_sha256).toBe(
      'c2d8db3fd71f1f8a6502c0c326f9f439f5563f776cae57377ecbf58c5a3ffb3f'
    );
  });

  it('does not manufacture coordination from one family or unknown tools', async () => {
    const oneFamily = await createOffensiveToolchainEvidence({
      sensor: 'mcp-proxy',
      runId: 'run-1',
      correlationSecret,
      invocations: [{ tool: 'nmap_scan' }, { tool: 'nmap_advanced_scan' }, { tool: 'unknown' }],
    });
    expect(oneFamily.offensive_toolchain.tool_families).toEqual(['network_reconnaissance']);
    expect(oneFamily.offensive_toolchain.invocation_count).toBe(2);
    expect(oneFamily.offensive_toolchain.dropped_tool_count).toBe(1);

    await expect(
      createOffensiveToolchainEvidence({
        sensor: 'mcp-proxy',
        runId: 'run-2',
        correlationSecret,
        invocations: [{ tool: 'unknown' }],
      })
    ).rejects.toThrow('no reviewed offensive tools');
  });

  it('rejects weak correlation secrets and unbounded reporter labels', async () => {
    const base = {
      sensor: 'mcp-proxy',
      runId: 'run-1',
      correlationSecret,
      invocations: [{ tool: 'nmap_scan' }],
    };
    await expect(
      createOffensiveToolchainEvidence({ ...base, correlationSecret: 'too-short' })
    ).rejects.toThrow('correlationSecret');
    await expect(
      createOffensiveToolchainEvidence({ ...base, sensor: 'customer email@example.com' })
    ).rejects.toThrow('stable identifier');
    await expect(
      createOffensiveToolchainEvidence({
        ...base,
        invocations: [{ tool: 'x'.repeat(129) }],
      })
    ).rejects.toThrow('tool must be 1-128 characters');
  });

  it('reports the bounded envelope through the authenticated SDK route', async () => {
    const calls: unknown[] = [];
    const previousFetch = globalThis.fetch;
    globalThis.fetch = jest.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      calls.push(JSON.parse(String(init?.body)));
      return new Response(
        JSON.stringify({
          decision: 'allow',
          confidence: 90,
          threat_level: 'LOW',
          bot_detected: true,
          detection_id: 'toolchain-detection',
          rule_enforced: false,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      );
    }) as typeof fetch;
    try {
      const sdk = new WebDecoy({ apiKey: 'sk_test_toolchain' });
      const response = await sdk.reportOffensiveToolchain({
        sensor: 'mcp-proxy',
        runId: 'raw-run-id',
        correlationSecret,
        invocations: [{ tool: 'nmap_scan' }, { tool: 'nuclei_scan' }],
      });
      expect(response.detection_id).toBe('toolchain-detection');
      expect(calls).toHaveLength(1);
      expect((calls[0] as { request_metadata: { ip: string } }).request_metadata.ip).toBe('0.0.0.0');
      const wire = JSON.stringify(calls[0]);
      expect(wire).toContain('offensive_toolchain');
      expect(wire).not.toContain('raw-run-id');
      expect(wire).not.toContain(correlationSecret);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});
