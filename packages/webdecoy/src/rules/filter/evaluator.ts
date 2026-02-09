/**
 * Filter Expression Evaluator
 * Walks an AST and evaluates it against a context
 */

import type { ASTNode } from './parser';
import type { RuleContext } from '../types';

const MAX_REGEX_LENGTH = 500;

/**
 * Evaluate an AST node against a rule context.
 * Returns the evaluated value (boolean, number, string, array, or undefined).
 */
export function evaluate(node: ASTNode, context: RuleContext): any {
  switch (node.kind) {
    case 'bool':
      return node.value;

    case 'number':
      return node.value;

    case 'string':
      return node.value;

    case 'array':
      return node.elements.map((el) => evaluate(el, context));

    case 'property':
      return resolveProperty(node.path, context);

    case 'call':
      return resolveCall(node.object, node.method, node.args, context);

    case 'unary':
      return evaluateUnary(node.op, node.operand, context);

    case 'binary':
      return evaluateBinary(node.op, node.left, node.right, context);
  }
}

/**
 * Resolve a dotted property path against the context.
 *
 * Supported namespaces:
 *   ip.vpn, ip.proxy, ip.tor, ip.relay, ip.hosting  → enrichment.security.*
 *   ip.country, ip.country_name, ip.city, ip.timezone → enrichment.location.*
 *   ip.asn, ip.asn_org → enrichment.network.*
 *   ip.abuse_score, ip.total_reports, ip.is_high_risk → enrichment.reputation.*
 *   req.path, req.method, req.ip, req.user_agent → context fields
 */
function resolveProperty(path: string[], context: RuleContext): any {
  const namespace = path[0];
  const prop = path.slice(1).join('.');

  if (namespace === 'ip') {
    const e = context.enrichment;
    if (!e) return undefined;

    // Security
    if (prop === 'vpn') return e.security.vpn;
    if (prop === 'proxy') return e.security.proxy;
    if (prop === 'tor') return e.security.tor;
    if (prop === 'relay') return e.security.relay;
    if (prop === 'hosting') return e.security.hosting;

    // Location
    if (prop === 'country') return e.location.country;
    if (prop === 'country_name') return e.location.country_name;
    if (prop === 'city') return e.location.city;
    if (prop === 'timezone') return e.location.timezone;

    // Network
    if (prop === 'asn') return e.network.asn;
    if (prop === 'asn_org') return e.network.asn_org;

    // Reputation
    if (prop === 'abuse_score') return e.reputation.abuse_score;
    if (prop === 'total_reports') return e.reputation.total_reports;
    if (prop === 'is_high_risk') return e.reputation.is_high_risk;

    return undefined;
  }

  if (namespace === 'req') {
    if (prop === 'path') return context.path;
    if (prop === 'method') return context.method;
    if (prop === 'ip') return context.ip;
    if (prop === 'user_agent') return context.userAgent;
    return undefined;
  }

  // Single ident with no namespace — treat as boolean property shorthand
  if (path.length === 1) return undefined;

  return undefined;
}

/**
 * Resolve a function call like req.header("x-api-key")
 */
function resolveCall(
  object: string[],
  method: string,
  args: ASTNode[],
  context: RuleContext,
): any {
  const namespace = object[0];

  if (namespace === 'req' && method === 'header') {
    if (args.length !== 1) return undefined;
    const headerName = evaluate(args[0], context);
    if (typeof headerName !== 'string') return undefined;
    return context.headers[headerName.toLowerCase()];
  }

  return undefined;
}

function evaluateUnary(op: string, operand: ASTNode, context: RuleContext): any {
  const val = evaluate(operand, context);
  if (op === 'not') {
    if (val === undefined) return false;
    return !val;
  }
  return undefined;
}

function evaluateBinary(
  op: string,
  left: ASTNode,
  right: ASTNode,
  context: RuleContext,
): any {
  // Short-circuit for boolean operators
  if (op === 'and') {
    const l = evaluate(left, context);
    if (l === undefined || l === false) return false;
    const r = evaluate(right, context);
    if (r === undefined) return false;
    return !!r;
  }

  if (op === 'or') {
    const l = evaluate(left, context);
    if (l === undefined ? false : !!l) return true;
    const r = evaluate(right, context);
    if (r === undefined) return false;
    return !!r;
  }

  const l = evaluate(left, context);
  const r = evaluate(right, context);

  // Undefined comparisons always return false (fail-open)
  if (l === undefined || r === undefined) return false;

  switch (op) {
    case '==': return l === r;
    case '!=': return l !== r;
    case '>': return typeof l === 'number' && typeof r === 'number' && l > r;
    case '>=': return typeof l === 'number' && typeof r === 'number' && l >= r;
    case '<': return typeof l === 'number' && typeof r === 'number' && l < r;
    case '<=': return typeof l === 'number' && typeof r === 'number' && l <= r;

    case 'in': {
      if (!Array.isArray(r)) return false;
      return r.includes(l);
    }

    case 'not in': {
      if (!Array.isArray(r)) return false;
      return !r.includes(l);
    }

    case 'matches': {
      if (typeof l !== 'string' || typeof r !== 'string') return false;
      if (r.length > MAX_REGEX_LENGTH) return false;
      try {
        return new RegExp(r).test(l);
      } catch {
        return false;
      }
    }

    default:
      return false;
  }
}
