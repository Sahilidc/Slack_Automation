import re

# Patterns for secrets
PATTERNS = {
    "email": {
        "regex": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        "severity": 2,
    },
    "api_key": {
        "regex": r'(?i)(sk_live_[0-9a-zA-Z]{24}|AKIA[0-9A-Z]{16}|[A-Za-z0-9_-]{32,})',
        "severity": 4,
    },
    "password": {
        "regex": r'(?i)(password|pwd|token)[=:]?\s*["\']?[A-Za-z0-9!@#$%^&*()_+=-]{6,}["\']?',
        "severity": 5,
    },
}

def redact(value):
    if len(value) <= 6:
        return '***'
    return value[:4] + '*' * 4 + value[-4:]

def scan_message_for_secrets(text):
    findings = []

    for key, rule in PATTERNS.items():
        matches = re.findall(rule["regex"], text)
        for match in matches:
            redacted = redact(match)
            severity = rule["severity"]
            summary = f"Found {key.upper()}: {redacted} (Severity {severity})"
            findings.append({
                "type": key,
                "original": match,
                "redacted": redacted,
                "severity": severity,
                "summary": summary
            })

    return findings
