import { hmacSha256Hex, sha256Hex } from './webcrypto';
import type {
  FrameworkEvidenceObservation,
  OffensiveToolFamily,
  OffensiveToolchainObservation,
} from './types';

const TOOLCHAIN_REGISTRY_REVISION = 1;
const FRAMEWORK_REGISTRY_REVISION = 5;

const reviewedTools: Readonly<Record<string, OffensiveToolFamily>> = Object.freeze({
  nmap_scan: 'network_reconnaissance',
  nmap_advanced_scan: 'network_reconnaissance',
  masscan_scan: 'network_reconnaissance',
  nuclei_scan: 'vulnerability_scanning',
  sqlmap_scan: 'injection_testing',
  metasploit_run: 'exploitation',
});

export interface OffensiveToolInvocation {
  /** Reviewed tool identifier. Unknown identifiers are counted and dropped. */
  tool: string;
  /** Number of argument values the sensor removed before reporting. */
  redactedArgumentCount?: number;
}

export interface OffensiveToolchainEvidenceInput {
  /** Stable name for the authenticated model-plane sensor, at most 128 characters. */
  sensor: string;
  /** Raw run ID used only as HMAC input. It is never returned. */
  runId: string;
  /** Deployment-held HMAC secret used to pseudonymize run IDs. */
  correlationSecret: string;
  invocations: readonly OffensiveToolInvocation[];
  /** Set only when instrumenting the official HexStrike AI MCP orchestrator. */
  orchestrator?: 'hexstrike_ai';
}

export interface OffensiveToolchainEvidence {
  offensive_toolchain: OffensiveToolchainObservation;
  framework_evidence?: FrameworkEvidenceObservation;
}

/**
 * Build the strict model-plane evidence accepted by WebDecoy ingest.
 *
 * Tool arguments, results, prompts, credentials and targets are intentionally
 * absent from this API. Unknown tool names are counted and discarded. One
 * recognized family can be reported for coverage but does not correlate; the
 * backend requires coordinated use of at least two reviewed families.
 */
export async function createOffensiveToolchainEvidence(
  input: OffensiveToolchainEvidenceInput
): Promise<OffensiveToolchainEvidence> {
  const sensor = input.sensor.trim();
  if (!/^[a-z0-9][a-z0-9_.-]{0,127}$/i.test(sensor)) {
    throw new Error('sensor must be a 1-128 character stable identifier');
  }
  if (!input.runId || input.runId.length > 1024) {
    throw new Error('runId must be 1-1024 characters');
  }
  if (input.correlationSecret.length < 32 || input.correlationSecret.length > 4096) {
    throw new Error('correlationSecret must be 32-4096 characters');
  }
  if (
    !Array.isArray(input.invocations) ||
    input.invocations.length === 0 ||
    input.invocations.length > 256
  ) {
    throw new Error('invocations must contain 1-256 entries');
  }

  const sequence: OffensiveToolFamily[] = [];
  let redactedArgumentCount = 0;
  let droppedToolCount = 0;
  for (const invocation of input.invocations) {
    if (!invocation.tool || invocation.tool.length > 128) {
      throw new Error('tool must be 1-128 characters');
    }
    const redacted = invocation.redactedArgumentCount ?? 0;
    if (!Number.isInteger(redacted) || redacted < 0 || redacted > 1024) {
      throw new Error('redactedArgumentCount must be an integer from 0 through 1024');
    }
    const family = reviewedTools[invocation.tool.trim().toLowerCase()];
    if (!family) {
      droppedToolCount++;
      continue;
    }
    sequence.push(family);
    redactedArgumentCount += redacted;
    if (redactedArgumentCount > 1024) throw new Error('redacted argument count exceeds 1024');
  }
  if (sequence.length === 0) throw new Error('no reviewed offensive tools were observed');

  const families = [...new Set(sequence)].sort();
  const offensive_toolchain: OffensiveToolchainObservation = {
    schema_version: 1,
    registry_revision: TOOLCHAIN_REGISTRY_REVISION,
    plane: 'model_api',
    sensor,
    run_correlation_id: await hmacSha256Hex(input.correlationSecret, input.runId),
    tool_families: families,
    invocation_count: sequence.length,
    family_set_sha256: await fingerprintIDs(families),
    sequence_sha256: await sha256Hex(sequence.join('\n')),
    redacted_argument_count: redactedArgumentCount,
    dropped_tool_count: droppedToolCount,
  };

  const evidence: OffensiveToolchainEvidence = { offensive_toolchain };
  if (input.orchestrator === 'hexstrike_ai') {
    evidence.framework_evidence = await hexStrikeEvidence();
  }
  return evidence;
}

async function hexStrikeEvidence(): Promise<FrameworkEvidenceObservation> {
  const family = {
    family_id: 'orchestrator_identity',
    count: 1,
    sha256: await fingerprintIDs(['hexstrike-ai-mcp']),
  };
  return {
    schema_version: 1,
    registry_revision: FRAMEWORK_REGISTRY_REVISION,
    framework: 'hexstrike_ai',
    plane: 'model_api',
    evidence: [family],
    observation_sha256: await fingerprintEvidence([family]),
  };
}

async function fingerprintIDs(values: readonly string[]): Promise<string> {
  const canonical = [
    ...new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean)),
  ].sort();
  return sha256Hex(canonical.join('\n'));
}

async function fingerprintEvidence(
  evidence: ReadonlyArray<{ family_id: string; count: number; sha256: string }>
): Promise<string> {
  const canonical = evidence.map(
    (value) =>
      `${value.family_id.trim().toLowerCase()}\0${value.count}\0${value.sha256.trim().toLowerCase()}`
  );
  return fingerprintIDs(canonical);
}
