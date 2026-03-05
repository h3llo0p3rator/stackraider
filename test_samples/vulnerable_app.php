<?php
/**
 * SAMPLE VULNERABLE PHP CODE FOR TESTING
 * This file contains intentional vulnerabilities for scanner verification.
 * DO NOT USE IN PRODUCTION!
 */

// ============================================
// PHP-CMD-001: Command Injection via system()
// ============================================
$host = $_GET['host'];
system("ping -c 4 " . $host);

// ============================================
// PHP-CMD-002: Command Injection via exec()
// ============================================
$filename = $_POST['file'];
exec("cat " . $filename, $output);

// ============================================
// PHP-CMD-004: Code Injection via eval()
// ============================================
$code = $_REQUEST['code'];
eval($code);

// ============================================
// PHP-SQL-001: SQL Injection
// ============================================
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '" . $id . "'";
$result = mysqli_query($conn, $query);

// ============================================
// PHP-SQL-003: Unsafe PDO Query
// ============================================
$username = $_POST['username'];
$stmt = $pdo->query("SELECT * FROM users WHERE username = '" . $username . "'");

// ============================================
// PHP-LFI-001: Local File Inclusion
// ============================================
$page = $_GET['page'];
include($page);

// Another LFI variant
$template = $_REQUEST['template'];
require_once($template . '.php');

// ============================================
// PHP-PATH-001: Path Traversal
// ============================================
$file = $_GET['download'];
$content = file_get_contents('/var/uploads/' . $file);
echo $content;

// Write with user input
$logfile = $_POST['log'];
file_put_contents($logfile, $data);

// ============================================
// PHP-UPLOAD-001: Unrestricted File Upload
// ============================================
if (isset($_FILES['avatar'])) {
    $target = '/var/www/uploads/' . $_FILES['avatar']['name'];
    move_uploaded_file($_FILES['avatar']['tmp_name'], $target);
}

// ============================================
// PHP-XSS-001: Cross-Site Scripting
// ============================================
$name = $_GET['name'];
echo "Hello, " . $name;

$search = $_POST['search'];
print "Results for: " . $search;

// ============================================
// PHP-DESER-001: Insecure Deserialization
// ============================================
$data = $_COOKIE['user_prefs'];
$prefs = unserialize($data);

$payload = base64_decode($_POST['data']);
$obj = unserialize($payload);

// ============================================
// PHP-SSRF-001: Server-Side Request Forgery
// ============================================
$url = $_GET['url'];
$content = file_get_contents($url);
echo $content;

// SSRF via cURL
$target = $_POST['target'];
$ch = curl_init($target);
curl_exec($ch);

// ============================================
// PHP-AUTH-001: Hardcoded Credentials
// ============================================
$db_password = 'supersecretpassword123';
$api_key = 'sk_live_abcdef123456789';

define('MYSQL_PASSWORD', 'admin123');

// ============================================
// PHP-AUTH-002: Weak Password Comparison
// ============================================
if ($_POST['password'] == $stored_hash) {
    login_user();
}

// ============================================
// PHP-INFO-001: phpinfo() Exposure
// ============================================
phpinfo();

// ============================================
// PHP-INFO-002: Error Display
// ============================================
error_reporting(E_ALL);
display_errors(1);

// ============================================
// PHP-XXE-001: XML External Entity
// ============================================
$xml = $_POST['xml'];
$doc = simplexml_load_string($xml);

$xmlData = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($xmlData);

// ============================================
// PHP-CONFIG-002: Weak Cryptography
// ============================================
$password = $_POST['password'];
$hash = md5($password);

$pass = $_POST['pass'];
$hashed = sha1($pass);

// ============================================
// PHP-HEADER-001: Header Injection
// ============================================
$redirect = $_GET['redirect'];
header("Location: " . $redirect);

// ============================================
// PHP-HEADER-002: Open Redirect
// ============================================
$url = $_GET['next'];
header("Location: " . $url);

// ============================================
// PHP-LDAP-001: LDAP Injection
// ============================================
$username = $_POST['username'];
$filter = "(uid=" . $username . ")";
ldap_search($ldap, $base_dn, $filter);

// ============================================
// PHP-CMD-005: preg_replace /e
// ============================================
$input = $_GET['input'];
preg_replace('/(.*)/e', 'strtoupper("\\1")', $input);

?>
