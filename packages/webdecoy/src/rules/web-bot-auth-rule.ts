/**
 * Web Bot Auth rule (the main application repo).
 *
 * Acts on the Web Bot Auth verdict the SDK computes before rule evaluation
 * (`context.agent`). Its headline job is to make **impersonation deny-able in
 * middleware**: a request forging a known agent's identity (a signature that
 * claims a curated agent's key but fails cryptographic verification) is a
 * tripwire-grade signal, denied by default.
 *
 * Verification itself is async (it may touch a directory cache), so — like the
 * filter rules and their IP enrichment — the verdict is precomputed into the
 * context and this rule stays synchronous.
 */

import type { Rule, RuleContext, RuleResult } from './types';
import type { AgentCategory } from '../agent/types';

export interface WebBotAuthConfig {
  /**
   * Action when a request **impersonates** a known agent (signature matched a
   * curated key but failed verification / window). Default `'DENY'`.
   */
  onImpersonation?: 'DENY' | 'THROTTLE' | 'ALLOW';
  /**
   * Action when a Web Bot Auth signature is present but **unverifiable**
   * (unknown keyid, malformed). Default `'ALLOW'` — an unknown signer is not
   * proof of abuse; leave the decision to detection/other rules. Set `'DENY'`
   * to require that every signed agent be one you trust.
   */
  onClaimed?: 'DENY' | 'THROTTLE' | 'ALLOW';
  /**
   * Restrict which categories of **verified** agents this rule treats as
   * acceptable. When set, a verified agent whose category is not listed is
   * handled per {@link onClaimed} (i.e. its signature checks out, but you
   * don't want that kind of agent). When omitted, all verified agents pass.
   */
  allowCategories?: AgentCategory[];
  /** Log the violation but never block. Default `false`. */
  dryRun?: boolean;
}

export class WebBotAuthRule implements Rule {
  readonly name = 'web-bot-auth';
  private readonly onImpersonation: 'DENY' | 'THROTTLE' | 'ALLOW';
  private readonly onClaimed: 'DENY' | 'THROTTLE' | 'ALLOW';
  private readonly allowCategories?: Set<AgentCategory>;
  private readonly dryRun: boolean;

  constructor(config: WebBotAuthConfig = {}) {
    this.onImpersonation = config.onImpersonation ?? 'DENY';
    this.onClaimed = config.onClaimed ?? 'ALLOW';
    this.allowCategories = config.allowCategories ? new Set(config.allowCategories) : undefined;
    this.dryRun = config.dryRun ?? false;
  }

  evaluate(context: RuleContext): RuleResult {
    const verdict = context.agent;
    if (!verdict || verdict.status === 'none') return this.allow();

    if (verdict.status === 'impersonation') {
      return this.act(this.onImpersonation, 'agent_impersonation', {
        agentName: verdict.agentName,
        category: verdict.category,
        keyId: verdict.keyId,
        detail: verdict.reason,
      });
    }

    if (verdict.status === 'claimed') {
      return this.act(this.onClaimed, 'agent_unverifiable', {
        keyId: verdict.keyId,
        detail: verdict.reason,
      });
    }

    // verified — pass, unless a category filter excludes it.
    if (this.allowCategories && verdict.category && !this.allowCategories.has(verdict.category)) {
      return this.act(this.onClaimed, 'agent_category_not_allowed', {
        agentName: verdict.agentName,
        category: verdict.category,
        keyId: verdict.keyId,
      });
    }
    return this.allow();
  }

  private act(
    action: 'DENY' | 'THROTTLE' | 'ALLOW',
    verdict: string,
    detail: Record<string, unknown>,
  ): RuleResult {
    if (action === 'ALLOW') return this.allow();
    return {
      action: this.dryRun ? 'ALLOW' : action,
      rule: this.name,
      reason: reasonFor(verdict),
      metadata: { verdict, dryRun: this.dryRun, ...detail },
    };
  }

  private allow(): RuleResult {
    return { action: 'ALLOW', rule: this.name };
  }
}

function reasonFor(verdict: string): string {
  switch (verdict) {
    case 'agent_impersonation':
      return 'Web Bot Auth signature failed verification (agent impersonation)';
    case 'agent_unverifiable':
      return 'Web Bot Auth signature could not be verified';
    case 'agent_category_not_allowed':
      return 'Verified agent category is not allowed';
    default:
      return 'Web Bot Auth rule triggered';
  }
}

/**
 * Deny requests that impersonate a verified AI agent (default), acting on the
 * SDK's local Web Bot Auth verification.
 *
 * @example
 * ```ts
 * import { WebDecoy, webBotAuth } from '@webdecoy/node';
 *
 * const wd = new WebDecoy({ rules: [webBotAuth()] });
 * ```
 */
export function webBotAuth(config: WebBotAuthConfig = {}): WebBotAuthRule {
  return new WebBotAuthRule(config);
}
