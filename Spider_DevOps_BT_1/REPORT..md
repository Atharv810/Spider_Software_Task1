# Vault Sweep Report

## Threat Patterns Detected

We flagged the following dangerous patterns:

- rm -rf → destructive file deletion
- mkfs → filesystem formatting
- shutdown / reboot → system disruption
- curl/wget piped to sh/bash → remote code execution risk
- /dev/tcp → reverse shell backdoor
- world writable scripts → unauthorized modification risk

---

## Environment File Validation

We only kept valid environment variables:

### Valid format rules:
- KEY=VALUE format only
- No spaces around '='
- Keys must be uppercase with underscores
- No quotes allowed
- No system sensitive keys

### Rejected cases:
- PASSWORD / SECRET / TOKEN → sensitive data
- PATH modifications → system risk
- quoted values → insecure format
- malformed variables like `KEY = value`

---

## Implementation Notes

- Used recursive scanning with `find`
- Used regex validation for threats and env parsing
- Permissions checked using `stat`
- Logging implemented with timestamps
- Interactive permission fixing added for world-writable scripts

---

## Output

- vault_sweep.log contains all audit logs
- .env.sanitized generated per env file