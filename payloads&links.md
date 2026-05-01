# Payloads & Links Reference

This document provides descriptions of the payload files available in the `payloads/` directory and their intended use cases during a security audit.

## Payload Files

### payloads.txt
- **Description**: A comprehensive collection of multi-vector SQL injection strings targeting various database engines (MySQL, PostgreSQL, MSSQL, Oracle, and SQLite).
- **Contents**:
    - **Fuzzing Characters**: Basic symbols like `'`, `"`, and `\` used to trigger initial syntax errors.
    - **Tautologies**: Classic bypasses such as `' OR 1=1--` and `1 OR 1=1`.
    - **Time-Based Payloads**: Database-specific sleep commands (e.g., `pg_sleep(10)`, `WAITFOR DELAY '0:0:5'`) to detect blind vulnerabilities.
    - **Union-Based**: Structural payloads designed to append results from other tables using `UNION SELECT`.
    - **Advanced/OOB**: Payloads targeting Out-of-Band exfiltration (e.g., DNS/HTTP requests via Burp Collaborator) and complex conditional logic using `CASE` statements.
    - **WAF Bypass**: Encoded and obfuscated strings intended to evade simple pattern-matching firewalls.
