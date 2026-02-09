/**
 * Filter Expression Parser
 * Recursive descent parser producing a typed AST
 *
 * Grammar:
 *   expression   → or_expr
 *   or_expr      → and_expr ( "or" and_expr )*
 *   and_expr     → unary ( "and" unary )*
 *   unary        → "not" unary | comparison
 *   comparison   → primary ( ("==" | "!=" | ">" | ">=" | "<" | "<=" | "in" | "not" "in" | "matches") primary )?
 *   primary      → BOOL | NUMBER | STRING | property | array | "(" expression ")"
 *   property     → IDENT ( "." IDENT )* ( "(" STRING ")" )?
 *   array        → "[" ( primary ( "," primary )* )? "]"
 */

import { Token, TokenType, Tokenizer } from './tokenizer';

// AST Node types
export type ASTNode =
  | BoolLiteral
  | NumberLiteral
  | StringLiteral
  | ArrayLiteral
  | PropertyAccess
  | FunctionCall
  | BinaryOp
  | UnaryOp;

export interface BoolLiteral { kind: 'bool'; value: boolean; }
export interface NumberLiteral { kind: 'number'; value: number; }
export interface StringLiteral { kind: 'string'; value: string; }
export interface ArrayLiteral { kind: 'array'; elements: ASTNode[]; }
export interface PropertyAccess { kind: 'property'; path: string[]; }
export interface FunctionCall { kind: 'call'; object: string[]; method: string; args: ASTNode[]; }
export interface BinaryOp { kind: 'binary'; op: string; left: ASTNode; right: ASTNode; }
export interface UnaryOp { kind: 'unary'; op: string; operand: ASTNode; }

export class Parser {
  private tokens: Token[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = new Tokenizer(source).tokenize();
  }

  parse(): ASTNode {
    const ast = this.orExpr();
    this.expect(TokenType.EOF, 'Expected end of expression');
    return ast;
  }

  private orExpr(): ASTNode {
    let left = this.andExpr();
    while (this.match(TokenType.OR)) {
      const right = this.andExpr();
      left = { kind: 'binary', op: 'or', left, right };
    }
    return left;
  }

  private andExpr(): ASTNode {
    let left = this.unary();
    while (this.match(TokenType.AND)) {
      const right = this.unary();
      left = { kind: 'binary', op: 'and', left, right };
    }
    return left;
  }

  private unary(): ASTNode {
    if (this.match(TokenType.NOT)) {
      // Check for "not in" pattern
      if (this.check(TokenType.IN)) {
        // Backtrack: this is handled in comparison as "not in"
        this.pos--;
        return this.comparison();
      }
      const operand = this.unary();
      return { kind: 'unary', op: 'not', operand };
    }
    return this.comparison();
  }

  private comparison(): ASTNode {
    let left = this.primary();

    // Check for comparison operators
    if (this.match(TokenType.EQ)) return { kind: 'binary', op: '==', left, right: this.primary() };
    if (this.match(TokenType.NEQ)) return { kind: 'binary', op: '!=', left, right: this.primary() };
    if (this.match(TokenType.GT)) return { kind: 'binary', op: '>', left, right: this.primary() };
    if (this.match(TokenType.GTE)) return { kind: 'binary', op: '>=', left, right: this.primary() };
    if (this.match(TokenType.LT)) return { kind: 'binary', op: '<', left, right: this.primary() };
    if (this.match(TokenType.LTE)) return { kind: 'binary', op: '<=', left, right: this.primary() };
    if (this.match(TokenType.IN)) return { kind: 'binary', op: 'in', left, right: this.primary() };
    if (this.match(TokenType.MATCHES)) return { kind: 'binary', op: 'matches', left, right: this.primary() };

    // Check for "not in"
    if (this.check(TokenType.NOT) && this.checkAhead(TokenType.IN)) {
      this.advance(); // consume 'not'
      this.advance(); // consume 'in'
      return { kind: 'binary', op: 'not in', left, right: this.primary() };
    }

    return left;
  }

  private primary(): ASTNode {
    // Boolean literals
    if (this.check(TokenType.BOOL)) {
      const token = this.advance();
      return { kind: 'bool', value: token.value === 'true' };
    }

    // Number literals
    if (this.check(TokenType.NUMBER)) {
      const token = this.advance();
      return { kind: 'number', value: parseFloat(token.value) };
    }

    // String literals
    if (this.check(TokenType.STRING)) {
      const token = this.advance();
      return { kind: 'string', value: token.value };
    }

    // Array literals
    if (this.match(TokenType.LBRACKET)) {
      const elements: ASTNode[] = [];
      if (!this.check(TokenType.RBRACKET)) {
        elements.push(this.primary());
        while (this.match(TokenType.COMMA)) {
          elements.push(this.primary());
        }
      }
      this.expect(TokenType.RBRACKET, 'Expected "]"');
      return { kind: 'array', elements };
    }

    // Parenthesized expression
    if (this.match(TokenType.LPAREN)) {
      const expr = this.orExpr();
      this.expect(TokenType.RPAREN, 'Expected ")"');
      return expr;
    }

    // Property access: ident.ident.ident or ident.ident("arg")
    if (this.check(TokenType.IDENT)) {
      const path: string[] = [this.advance().value];
      while (this.match(TokenType.DOT)) {
        if (!this.check(TokenType.IDENT)) {
          throw new Error(`Expected identifier after "." at position ${this.current().position}`);
        }
        path.push(this.advance().value);
      }

      // Check for function call: req.header("x-api-key")
      if (this.match(TokenType.LPAREN)) {
        const method = path.pop()!;
        const args: ASTNode[] = [];
        if (!this.check(TokenType.RPAREN)) {
          args.push(this.primary());
          while (this.match(TokenType.COMMA)) {
            args.push(this.primary());
          }
        }
        this.expect(TokenType.RPAREN, 'Expected ")"');
        return { kind: 'call', object: path, method, args };
      }

      return { kind: 'property', path };
    }

    throw new Error(`Unexpected token "${this.current().value}" at position ${this.current().position}`);
  }

  // Helper methods
  private current(): Token { return this.tokens[this.pos]; }
  private advance(): Token { return this.tokens[this.pos++]; }
  private check(type: TokenType): boolean { return this.current().type === type; }
  private checkAhead(type: TokenType): boolean { return this.pos + 1 < this.tokens.length && this.tokens[this.pos + 1].type === type; }
  private match(type: TokenType): boolean {
    if (this.check(type)) { this.advance(); return true; }
    return false;
  }
  private expect(type: TokenType, message: string): Token {
    if (this.check(type)) return this.advance();
    throw new Error(`${message}, got "${this.current().value}" at position ${this.current().position}`);
  }
}
