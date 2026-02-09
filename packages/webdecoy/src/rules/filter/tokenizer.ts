/**
 * Filter Expression Tokenizer
 * Converts a filter expression string into a stream of tokens
 */

export enum TokenType {
  // Literals
  IDENT = 'IDENT',
  STRING = 'STRING',
  NUMBER = 'NUMBER',
  BOOL = 'BOOL',

  // Operators
  AND = 'AND',
  OR = 'OR',
  NOT = 'NOT',
  EQ = 'EQ',         // ==
  NEQ = 'NEQ',       // !=
  GT = 'GT',         // >
  GTE = 'GTE',       // >=
  LT = 'LT',        // <
  LTE = 'LTE',       // <=
  IN = 'IN',         // in
  MATCHES = 'MATCHES', // matches

  // Punctuation
  DOT = 'DOT',
  LPAREN = 'LPAREN',
  RPAREN = 'RPAREN',
  LBRACKET = 'LBRACKET',
  RBRACKET = 'RBRACKET',
  COMMA = 'COMMA',

  // Special
  EOF = 'EOF',
}

export interface Token {
  type: TokenType;
  value: string;
  position: number;
}

const KEYWORDS: Record<string, TokenType> = {
  and: TokenType.AND,
  or: TokenType.OR,
  not: TokenType.NOT,
  in: TokenType.IN,
  matches: TokenType.MATCHES,
  true: TokenType.BOOL,
  false: TokenType.BOOL,
};

export class Tokenizer {
  private source: string;
  private pos = 0;
  private tokens: Token[] = [];

  constructor(source: string) {
    this.source = source;
  }

  tokenize(): Token[] {
    while (this.pos < this.source.length) {
      this.skipWhitespace();
      if (this.pos >= this.source.length) break;

      const ch = this.source[this.pos];

      if (ch === '.' ) { this.tokens.push({ type: TokenType.DOT, value: '.', position: this.pos }); this.pos++; continue; }
      if (ch === '(' ) { this.tokens.push({ type: TokenType.LPAREN, value: '(', position: this.pos }); this.pos++; continue; }
      if (ch === ')' ) { this.tokens.push({ type: TokenType.RPAREN, value: ')', position: this.pos }); this.pos++; continue; }
      if (ch === '[' ) { this.tokens.push({ type: TokenType.LBRACKET, value: '[', position: this.pos }); this.pos++; continue; }
      if (ch === ']' ) { this.tokens.push({ type: TokenType.RBRACKET, value: ']', position: this.pos }); this.pos++; continue; }
      if (ch === ',' ) { this.tokens.push({ type: TokenType.COMMA, value: ',', position: this.pos }); this.pos++; continue; }

      // Comparison operators
      if (ch === '=' && this.peek(1) === '=') { this.tokens.push({ type: TokenType.EQ, value: '==', position: this.pos }); this.pos += 2; continue; }
      if (ch === '!' && this.peek(1) === '=') { this.tokens.push({ type: TokenType.NEQ, value: '!=', position: this.pos }); this.pos += 2; continue; }
      if (ch === '>' && this.peek(1) === '=') { this.tokens.push({ type: TokenType.GTE, value: '>=', position: this.pos }); this.pos += 2; continue; }
      if (ch === '<' && this.peek(1) === '=') { this.tokens.push({ type: TokenType.LTE, value: '<=', position: this.pos }); this.pos += 2; continue; }
      if (ch === '>') { this.tokens.push({ type: TokenType.GT, value: '>', position: this.pos }); this.pos++; continue; }
      if (ch === '<') { this.tokens.push({ type: TokenType.LT, value: '<', position: this.pos }); this.pos++; continue; }

      // String literals
      if (ch === '"' || ch === "'") { this.readString(ch); continue; }

      // Numbers
      if (this.isDigit(ch) || (ch === '-' && this.isDigit(this.peek(1)))) { this.readNumber(); continue; }

      // Identifiers and keywords
      if (this.isIdentStart(ch)) { this.readIdent(); continue; }

      throw new Error(`Unexpected character '${ch}' at position ${this.pos}`);
    }

    this.tokens.push({ type: TokenType.EOF, value: '', position: this.pos });
    return this.tokens;
  }

  private peek(offset: number): string {
    const idx = this.pos + offset;
    return idx < this.source.length ? this.source[idx] : '';
  }

  private skipWhitespace(): void {
    while (this.pos < this.source.length && /\s/.test(this.source[this.pos])) {
      this.pos++;
    }
  }

  private readString(quote: string): void {
    const start = this.pos;
    this.pos++; // skip opening quote
    let value = '';
    while (this.pos < this.source.length && this.source[this.pos] !== quote) {
      if (this.source[this.pos] === '\\') {
        this.pos++; // skip escape
      }
      value += this.source[this.pos];
      this.pos++;
    }
    if (this.pos >= this.source.length) {
      throw new Error(`Unterminated string at position ${start}`);
    }
    this.pos++; // skip closing quote
    this.tokens.push({ type: TokenType.STRING, value, position: start });
  }

  private readNumber(): void {
    const start = this.pos;
    if (this.source[this.pos] === '-') this.pos++;
    while (this.pos < this.source.length && this.isDigit(this.source[this.pos])) {
      this.pos++;
    }
    if (this.pos < this.source.length && this.source[this.pos] === '.') {
      this.pos++;
      while (this.pos < this.source.length && this.isDigit(this.source[this.pos])) {
        this.pos++;
      }
    }
    this.tokens.push({ type: TokenType.NUMBER, value: this.source.slice(start, this.pos), position: start });
  }

  private readIdent(): void {
    const start = this.pos;
    while (this.pos < this.source.length && this.isIdentPart(this.source[this.pos])) {
      this.pos++;
    }
    const value = this.source.slice(start, this.pos);
    const keyword = KEYWORDS[value.toLowerCase()];
    if (keyword) {
      this.tokens.push({ type: keyword, value: value.toLowerCase(), position: start });
    } else {
      this.tokens.push({ type: TokenType.IDENT, value, position: start });
    }
  }

  private isDigit(ch: string): boolean { return ch >= '0' && ch <= '9'; }
  private isIdentStart(ch: string): boolean { return /[a-zA-Z_]/.test(ch); }
  private isIdentPart(ch: string): boolean { return /[a-zA-Z0-9_]/.test(ch); }
}
