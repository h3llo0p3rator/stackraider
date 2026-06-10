#!/usr/bin/env python3
"""
JavaScript unminifier/beautifier module.
"""

import re
import argparse
import sys
from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum, auto


class TokenType(Enum):
    """Token types for JavaScript lexer."""
    STRING = auto()
    TEMPLATE = auto()
    REGEX = auto()
    COMMENT_SINGLE = auto()
    COMMENT_MULTI = auto()
    KEYWORD = auto()
    IDENTIFIER = auto()
    NUMBER = auto()
    OPERATOR = auto()
    PUNCTUATION = auto()
    WHITESPACE = auto()
    NEWLINE = auto()
    EOF = auto()


@dataclass
class Token:
    """Represents a lexical token."""
    type: TokenType
    value: str
    line: int
    col: int


class JSUnminifier:
    """JavaScript unminifier with proper handling of strings, regex, and comments."""
    
    # JavaScript keywords that should have space after
    KEYWORDS = {
        'await', 'break', 'case', 'catch', 'class', 'const', 'continue',
        'debugger', 'default', 'delete', 'do', 'else', 'enum', 'export',
        'extends', 'false', 'finally', 'for', 'function', 'if', 'import',
        'in', 'instanceof', 'let', 'new', 'null', 'return', 'static',
        'super', 'switch', 'this', 'throw', 'true', 'try', 'typeof',
        'undefined', 'var', 'void', 'while', 'with', 'yield', 'async',
        'of', 'get', 'set', 'from', 'as'
    }
    
    # Operators that should have spaces around them
    SPACED_OPERATORS = {
        '===', '!==', '==', '!=', '<=', '>=', '&&', '||', '??',
        '+=', '-=', '*=', '/=', '%=', '**=', '&=', '|=', '^=',
        '<<=', '>>=', '>>>=', '??=', '&&=', '||=',
        '=>', '...', '**',
        '+', '-', '*', '/', '%', '&', '|', '^', '<', '>', '=', '?', ':'
    }
    
    # Characters that increase indent
    INDENT_OPEN = {'{', '[', '('}
    
    # Characters that decrease indent
    INDENT_CLOSE = {'}', ']', ')'}
    
    def __init__(self, indent_size: int = 2, indent_char: str = ' '):
        self.indent_size = indent_size
        self.indent_char = indent_char
        self.indent_level = 0
        self.output: List[str] = []
        self.current_line: List[str] = []
        self.last_token: Optional[Token] = None
        self.in_for_loop = False
        self.paren_depth = 0
        self.for_paren_depth = 0
    
    def _get_indent(self) -> str:
        """Get current indentation string."""
        return self.indent_char * (self.indent_size * self.indent_level)
    
    def _flush_line(self):
        """Flush current line to output."""
        line = ''.join(self.current_line).rstrip()
        if line:
            self.output.append(self._get_indent() + line)
        else:
            self.output.append('')
        self.current_line = []
    
    def _needs_space_before(self, token: str, prev_token: Optional[str]) -> bool:
        """Determine if space is needed before token."""
        if not prev_token:
            return False
        
        # No space after opening brackets
        if prev_token in '([{':
            return False
        
        # No space before closing brackets
        if token in ')]}':
            return False
        
        # No space before/after dots
        if token == '.' or prev_token == '.':
            return False
        
        # No space before commas/semicolons
        if token in ',;':
            return False
        
        # No space after ! or ~ (unary)
        if prev_token in '!~':
            return False
        
        # No space in increment/decrement
        if token in ['++', '--'] or prev_token in ['++', '--']:
            return False
        
        # Space before opening brace (for readability)
        if token == '{':
            return True
        
        # Space after keywords
        if prev_token in self.KEYWORDS:
            return True
        
        # Space around operators
        if token in self.SPACED_OPERATORS or prev_token in self.SPACED_OPERATORS:
            # But not for unary +/-
            if token in '+-' and prev_token in '([{,;:=<>!&|?+*-/%^':
                return False
            if prev_token in '+-' and prev_token == token:  # ++ or --
                return False
            return True
        
        # Space after comma
        if prev_token == ',':
            return True
        
        return False
    
    def _tokenize(self, code: str) -> List[Token]:
        """Tokenize JavaScript code, preserving strings and comments."""
        tokens: List[Token] = []
        i = 0
        line = 1
        col = 1
        
        while i < len(code):
            start_col = col
            
            # Single-line comment
            if code[i:i+2] == '//':
                end = code.find('\n', i)
                if end == -1:
                    end = len(code)
                tokens.append(Token(TokenType.COMMENT_SINGLE, code[i:end], line, start_col))
                i = end
                col = end - code.rfind('\n', 0, end)
                continue
            
            # Multi-line comment
            if code[i:i+2] == '/*':
                end = code.find('*/', i + 2)
                if end == -1:
                    end = len(code)
                else:
                    end += 2
                comment = code[i:end]
                tokens.append(Token(TokenType.COMMENT_MULTI, comment, line, start_col))
                newlines = comment.count('\n')
                line += newlines
                if newlines:
                    col = len(comment) - comment.rfind('\n')
                else:
                    col += len(comment)
                i = end
                continue
            
            # String (single quote)
            if code[i] == "'":
                end = i + 1
                while end < len(code):
                    if code[end] == '\\':
                        end += 2
                    elif code[end] == "'":
                        end += 1
                        break
                    else:
                        end += 1
                tokens.append(Token(TokenType.STRING, code[i:end], line, start_col))
                col += end - i
                i = end
                continue
            
            # String (double quote)
            if code[i] == '"':
                end = i + 1
                while end < len(code):
                    if code[end] == '\\':
                        end += 2
                    elif code[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
                tokens.append(Token(TokenType.STRING, code[i:end], line, start_col))
                col += end - i
                i = end
                continue
            
            # Template literal
            if code[i] == '`':
                end = i + 1
                depth = 1
                while end < len(code) and depth > 0:
                    if code[end] == '\\':
                        end += 2
                    elif code[end] == '`':
                        depth -= 1
                        end += 1
                    elif code[end:end+2] == '${':
                        # Handle nested template expressions
                        brace_depth = 1
                        end += 2
                        while end < len(code) and brace_depth > 0:
                            if code[end] == '{':
                                brace_depth += 1
                            elif code[end] == '}':
                                brace_depth -= 1
                            elif code[end] == '`':
                                # Nested template
                                nested_end = end + 1
                                while nested_end < len(code) and code[nested_end] != '`':
                                    if code[nested_end] == '\\':
                                        nested_end += 2
                                    else:
                                        nested_end += 1
                                end = nested_end + 1
                                continue
                            end += 1
                    else:
                        end += 1
                template = code[i:end]
                tokens.append(Token(TokenType.TEMPLATE, template, line, start_col))
                newlines = template.count('\n')
                line += newlines
                if newlines:
                    col = len(template) - template.rfind('\n')
                else:
                    col += len(template)
                i = end
                continue
            
            # Regex (simple detection)
            if code[i] == '/' and i > 0:
                # Check if this could be a regex (after certain tokens)
                prev_char = code[i-1] if i > 0 else ''
                prev_nonws = ''
                j = i - 1
                while j >= 0 and code[j] in ' \t\n\r':
                    j -= 1
                if j >= 0:
                    prev_nonws = code[j]
                
                if prev_nonws in '(,=:[!&|?{};':
                    end = i + 1
                    while end < len(code):
                        if code[end] == '\\':
                            end += 2
                        elif code[end] == '/':
                            end += 1
                            # Consume flags
                            while end < len(code) and code[end] in 'gimsuy':
                                end += 1
                            break
                        elif code[end] == '\n':
                            break
                        elif code[end] == '[':
                            # Character class
                            end += 1
                            while end < len(code) and code[end] != ']':
                                if code[end] == '\\':
                                    end += 2
                                else:
                                    end += 1
                            end += 1
                        else:
                            end += 1
                    tokens.append(Token(TokenType.REGEX, code[i:end], line, start_col))
                    col += end - i
                    i = end
                    continue
            
            # Whitespace
            if code[i] in ' \t':
                end = i
                while end < len(code) and code[end] in ' \t':
                    end += 1
                tokens.append(Token(TokenType.WHITESPACE, code[i:end], line, start_col))
                col += end - i
                i = end
                continue
            
            # Newline
            if code[i] == '\n':
                tokens.append(Token(TokenType.NEWLINE, '\n', line, start_col))
                line += 1
                col = 1
                i += 1
                continue
            
            if code[i] == '\r':
                if i + 1 < len(code) and code[i+1] == '\n':
                    tokens.append(Token(TokenType.NEWLINE, '\r\n', line, start_col))
                    i += 2
                else:
                    tokens.append(Token(TokenType.NEWLINE, '\r', line, start_col))
                    i += 1
                line += 1
                col = 1
                continue
            
            # Multi-character operators
            for op_len in [4, 3, 2]:
                if code[i:i+op_len] in ['>>>=']:
                    tokens.append(Token(TokenType.OPERATOR, code[i:i+op_len], line, start_col))
                    col += op_len
                    i += op_len
                    break
                if op_len == 3 and code[i:i+op_len] in ['===', '!==', '>>>', '...', '**=', '>>=', '<<=', '&&=', '||=', '??=']:
                    tokens.append(Token(TokenType.OPERATOR, code[i:i+op_len], line, start_col))
                    col += op_len
                    i += op_len
                    break
                if op_len == 2 and code[i:i+op_len] in ['==', '!=', '<=', '>=', '&&', '||', '??', '++', '--', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '=>', '**', '>>', '<<']:
                    tokens.append(Token(TokenType.OPERATOR, code[i:i+op_len], line, start_col))
                    col += op_len
                    i += op_len
                    break
            else:
                # Single character operators/punctuation
                if code[i] in '+-*/%=<>&|^!~?:':
                    tokens.append(Token(TokenType.OPERATOR, code[i], line, start_col))
                    col += 1
                    i += 1
                    continue
                
                if code[i] in '(){}[];,.':
                    tokens.append(Token(TokenType.PUNCTUATION, code[i], line, start_col))
                    col += 1
                    i += 1
                    continue
                
                # Identifier or keyword
                if code[i].isalpha() or code[i] == '_' or code[i] == '$':
                    end = i + 1
                    while end < len(code) and (code[end].isalnum() or code[end] in '_$'):
                        end += 1
                    word = code[i:end]
                    if word in self.KEYWORDS:
                        tokens.append(Token(TokenType.KEYWORD, word, line, start_col))
                    else:
                        tokens.append(Token(TokenType.IDENTIFIER, word, line, start_col))
                    col += end - i
                    i = end
                    continue
                
                # Number
                if code[i].isdigit():
                    end = i + 1
                    # Handle hex, binary, octal
                    if code[i] == '0' and end < len(code) and code[end] in 'xXbBoO':
                        end += 1
                        while end < len(code) and (code[end].isalnum() or code[end] == '_'):
                            end += 1
                    else:
                        while end < len(code) and (code[end].isdigit() or code[end] in '._eE+-'):
                            if code[end] in 'eE' and end + 1 < len(code) and code[end+1] in '+-':
                                end += 2
                            else:
                                end += 1
                    # Handle BigInt
                    if end < len(code) and code[end] == 'n':
                        end += 1
                    tokens.append(Token(TokenType.NUMBER, code[i:end], line, start_col))
                    col += end - i
                    i = end
                    continue
                
                # Unknown character - keep as-is
                tokens.append(Token(TokenType.PUNCTUATION, code[i], line, start_col))
                col += 1
                i += 1
        
        tokens.append(Token(TokenType.EOF, '', line, col))
        return tokens
    
    def unminify(self, code: str) -> str:
        """
        Unminify/beautify JavaScript code.
        
        Args:
            code: Minified JavaScript code
            
        Returns:
            Formatted, readable JavaScript code
        """
        tokens = self._tokenize(code)
        self.output = []
        self.current_line = []
        self.indent_level = 0
        self.last_token = None
        self.in_for_loop = False
        self.paren_depth = 0
        self.for_paren_depth = 0
        self.brace_depth = 0
        self.bracket_depth = 0
        
        prev_value: Optional[str] = None
        prev_token: Optional[Token] = None
        
        i = 0
        while i < len(tokens):
            token = tokens[i]
            
            if token.type == TokenType.EOF:
                break
            
            # Skip original whitespace/newlines (we'll add our own)
            if token.type in (TokenType.WHITESPACE, TokenType.NEWLINE):
                i += 1
                continue
            
            # Handle comments
            if token.type == TokenType.COMMENT_SINGLE:
                if self.current_line:
                    self.current_line.append(' ')
                self.current_line.append(token.value)
                self._flush_line()
                prev_value = token.value
                prev_token = token
                i += 1
                continue
            
            if token.type == TokenType.COMMENT_MULTI:
                if self.current_line:
                    self._flush_line()
                for line in token.value.split('\n'):
                    self.output.append(self._get_indent() + line.strip())
                prev_value = token.value
                prev_token = token
                i += 1
                continue
            
            # Track for loops (don't break on semicolons inside for(...))
            if token.type == TokenType.KEYWORD and token.value == 'for':
                self.in_for_loop = True
                self.for_paren_depth = 0
            
            # Track parentheses
            if token.value == '(':
                self.paren_depth += 1
                if self.in_for_loop and self.for_paren_depth == 0:
                    self.for_paren_depth = self.paren_depth
            elif token.value == ')':
                if self.in_for_loop and self.paren_depth == self.for_paren_depth:
                    self.in_for_loop = False
                self.paren_depth -= 1
            
            # Handle closing brace - decrease indent BEFORE adding the brace
            if token.value == '}':
                if self.current_line:
                    self._flush_line()
                self.indent_level = max(0, self.indent_level - 1)
                self.brace_depth = max(0, self.brace_depth - 1)
            
            # Add space if needed
            if self._needs_space_before(token.value, prev_value) and self.current_line:
                self.current_line.append(' ')
            
            # Add the token
            self.current_line.append(token.value)
            
            # Handle newlines and indent changes after certain tokens
            if token.value == '{':
                self.brace_depth += 1
                self._flush_line()
                self.indent_level += 1
            elif token.value == '[':
                self.bracket_depth += 1
            elif token.value == ']':
                self.bracket_depth = max(0, self.bracket_depth - 1)
            elif token.value == '}':
                self._flush_line()
                # Check if followed by else, catch, finally, while (do-while)
                next_token = self._peek_next_nonws(tokens, i)
                if next_token and next_token.value in ('else', 'catch', 'finally', 'while'):
                    pass  # Will continue on same logical block
            elif token.value == ';':
                if not self.in_for_loop:
                    self._flush_line()
            elif token.value == ',':
                # Newline after comma in object literals (inside braces at top level)
                # but not inside arrays or function calls
                if self.brace_depth > 0 and self.paren_depth == 0 and self.bracket_depth == 0:
                    self._flush_line()
            
            prev_value = token.value
            prev_token = token
            self.last_token = token
            i += 1
        
        # Flush any remaining content
        if self.current_line:
            self._flush_line()
        
        return '\n'.join(self.output)
    
    def _peek_next_nonws(self, tokens: List[Token], current_idx: int) -> Optional[Token]:
        """Peek at next non-whitespace token."""
        i = current_idx + 1
        while i < len(tokens):
            if tokens[i].type not in (TokenType.WHITESPACE, TokenType.NEWLINE):
                return tokens[i]
            i += 1
        return None


def unminify_file(input_path: str, output_path: Optional[str] = None, 
                  indent_size: int = 2) -> str:
    """
    Unminify a JavaScript file.
    
    Args:
        input_path: Path to minified JS file
        output_path: Optional output path (default: input_path.unminified.js)
        indent_size: Number of spaces for indentation
        
    Returns:
        Path to the unminified file
    """
    input_file = Path(input_path)
    
    if output_path is None:
        output_path = str(input_file.with_suffix('.unminified' + input_file.suffix))
    
    code = input_file.read_text(encoding='utf-8', errors='ignore')
    
    unminifier = JSUnminifier(indent_size=indent_size)
    beautified = unminifier.unminify(code)
    
    Path(output_path).write_text(beautified, encoding='utf-8')
    
    return output_path


def unminify_string(code: str, indent_size: int = 2) -> str:
    """
    Unminify JavaScript code string.
    
    Args:
        code: Minified JavaScript code
        indent_size: Number of spaces for indentation
        
    Returns:
        Beautified JavaScript code
    """
    unminifier = JSUnminifier(indent_size=indent_size)
    return unminifier.unminify(code)


def main():
    """CLI entry point for unminifier."""
    parser = argparse.ArgumentParser(
        description='JavaScript/TypeScript Unminifier - Beautify minified code for security analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s bundle.min.js                      # Unminify to bundle.unminified.js
  %(prog)s bundle.min.js -o readable.js       # Specify output file
  %(prog)s bundle.min.js --indent 4           # Use 4-space indentation
  %(prog)s *.min.js                           # Unminify multiple files
  cat minified.js | %(prog)s -                # Read from stdin
        '''
    )
    
    parser.add_argument('files', nargs='+', help='JavaScript files to unminify (use - for stdin)')
    parser.add_argument('-o', '--output', help='Output file (only valid with single input file)')
    parser.add_argument('--indent', type=int, default=2, help='Indentation size (default: 2)')
    parser.add_argument('--stdout', action='store_true', help='Output to stdout instead of file')
    
    args = parser.parse_args()
    
    if args.output and len(args.files) > 1:
        print("Error: --output can only be used with a single input file", file=sys.stderr)
        return 1
    
    for input_file in args.files:
        if input_file == '-':
            # Read from stdin
            code = sys.stdin.read()
            result = unminify_string(code, indent_size=args.indent)
            print(result)
        else:
            if not Path(input_file).exists():
                print(f"Error: File not found: {input_file}", file=sys.stderr)
                continue
            
            if args.stdout:
                code = Path(input_file).read_text(encoding='utf-8', errors='ignore')
                result = unminify_string(code, indent_size=args.indent)
                print(result)
            else:
                output = unminify_file(input_file, args.output, indent_size=args.indent)
                print(f"✅ Unminified: {input_file} -> {output}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
