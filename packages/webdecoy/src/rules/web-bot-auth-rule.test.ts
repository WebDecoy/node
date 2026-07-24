import { webBotAuth } from './web-bot-auth-rule';
import type { RuleContext } from './types';
import type { AgentVerdict } from '../agent/types';

function ctx(agent?: AgentVerdict): RuleContext {
  return {
    ip: '1.2.3.4',
    path: '/',
    method: 'GET',
    headers: {},
    timestamp: Date.now(),
    agent,
  };
}

describe('webBotAuth rule', () => {
  it('denies an impersonation by default', () => {
    const r = webBotAuth().evaluate(ctx({ status: 'impersonation', keyId: 'k', reason: 'bad-signature' }));
    expect(r.action).toBe('DENY');
    expect(r.rule).toBe('web-bot-auth');
    expect(r.metadata?.verdict).toBe('agent_impersonation');
  });

  it('allows a verified agent', () => {
    const r = webBotAuth().evaluate(
      ctx({ status: 'verified', agentName: 'OpenAI', category: 'ai_crawlers', method: 'signature' }),
    );
    expect(r.action).toBe('ALLOW');
  });

  it('allows an unverifiable claim by default, denies it when onClaimed=DENY', () => {
    const verdict: AgentVerdict = { status: 'claimed', keyId: 'k', reason: 'unknown-key' };
    expect(webBotAuth().evaluate(ctx(verdict)).action).toBe('ALLOW');
    expect(webBotAuth({ onClaimed: 'DENY' }).evaluate(ctx(verdict)).action).toBe('DENY');
  });

  it('passes through when there is no agent verdict', () => {
    expect(webBotAuth().evaluate(ctx()).action).toBe('ALLOW');
    expect(webBotAuth().evaluate(ctx({ status: 'none' })).action).toBe('ALLOW');
  });

  it('honors dryRun — records the verdict but never blocks', () => {
    const r = webBotAuth({ dryRun: true }).evaluate(ctx({ status: 'impersonation', reason: 'bad-signature' }));
    expect(r.action).toBe('ALLOW');
    expect(r.metadata?.dryRun).toBe(true);
    expect(r.metadata?.verdict).toBe('agent_impersonation');
  });

  it('rejects a verified agent whose category is not allowed', () => {
    const rule = webBotAuth({ allowCategories: ['search_engines'], onClaimed: 'DENY' });
    const r = rule.evaluate(ctx({ status: 'verified', agentName: 'OpenAI', category: 'ai_crawlers' }));
    expect(r.action).toBe('DENY');
    expect(r.metadata?.verdict).toBe('agent_category_not_allowed');
  });

  it('accepts a verified agent whose category is allowed', () => {
    const rule = webBotAuth({ allowCategories: ['ai_crawlers'] });
    const r = rule.evaluate(ctx({ status: 'verified', agentName: 'OpenAI', category: 'ai_crawlers' }));
    expect(r.action).toBe('ALLOW');
  });
});
