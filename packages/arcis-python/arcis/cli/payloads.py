"""
Attack payload definitions for arcis scan.
Each category maps to a list of (label, payload) tuples.
The first payload in each category is the primary test vector.
"""

ATTACK_CATEGORIES = {
    "XSS": [
        ("script tag",          "<script>alert(1)</script>"),
        ("img onerror",         "<img src=x onerror=alert(1)>"),
        ("javascript URI",      "javascript:alert(document.cookie)"),
        ("svg onload",          "<svg onload=alert(1)>"),
    ],
    "SQL Injection": [
        ("OR bypass",           "' OR '1'='1' --"),
        ("UNION select",        "' UNION SELECT null,null,null--"),
        ("stacked query",       "'; DROP TABLE users--"),
        ("comment bypass",      "1/**/OR/**/1=1"),
    ],
    "SQL Blind": [
        ("SLEEP",               "'; SLEEP(5)--"),
        ("BENCHMARK",           "'; BENCHMARK(1000000,MD5(1))--"),
        ("WAITFOR",             "1; WAITFOR DELAY '0:0:5'--"),
    ],
    "NoSQL Injection": [
        ("$gt operator",        '{"$gt": ""}'),
        ("$where operator",     '{"$where": "1==1"}'),
        ("$ne operator",        '{"$ne": null}'),
        ("$regex operator",     '{"$regex": ".*"}'),
    ],
    "Path Traversal": [
        ("unix passwd",         "../../etc/passwd"),
        ("windows system32",    "..\\..\\windows\\system32\\cmd.exe"),
        ("url encoded",         "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("null byte",           "../../etc/passwd%00"),
    ],
    "Command Injection": [
        ("semicolon",           "; ls -la"),
        ("pipe",                "| whoami"),
        ("backtick",            "`id`"),
        ("ampersand",           "&& cat /etc/passwd"),
    ],
    "Prototype Pollution": [
        ("__proto__",           '{"__proto__": {"admin": true}}'),
        ("constructor",         '{"constructor": {"prototype": {"admin": true}}}'),
    ],
    "LDAP Injection": [
        ("wildcard",            "*)(uid=*))(|(uid=*"),
        ("OR bypass",           "admin)(&(password=*)"),
    ],
}

# Common field names to inject into, tried in order
DEFAULT_FIELDS = [
    "q", "query", "search", "input",
    "name", "username", "email",
    "data", "value", "text", "id",
]

# Status codes that indicate the request was blocked/rejected
BLOCKED_STATUS_CODES = {400, 403, 422, 429}
