/**
 * Local Web Bot Auth verification for the WebDecoy SDK.
 *
 * Verify whether an inbound request carries a cryptographically valid AI-agent
 * signature (RFC 9421, tag "web-bot-auth"), in-process, on Node and every
 * WinterCG edge runtime — no network on the warm path.
 */

export { AgentVerifier, createAgentVerifier } from './verifier';
export { DirectoryCache, DEFAULT_SIGNED_AGENT_DIRECTORIES } from './directory';

export type {
  AgentStatus,
  AgentCategory,
  AgentVerdict,
  AgentRequestInput,
  AgentVerifierOptions,
  SignedAgentDirectory,
} from './types';
