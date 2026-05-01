# SQL Injection (SQLi) Tutorial

SQL Injection is a critical vulnerability that occurs when an attacker can interfere with the queries an application makes to its database. This allows unauthorized access to data, modification of records, or even administrative control over the database server.

## Core Methodology

The `SQLi_checker` tool automates the discovery process using several industry-standard techniques:

### 1. Error-Based Detection
The simplest way to find SQLi. We inject characters like single quotes (`'`) to break the SQL syntax. If the application is vulnerable and improperly configured, the database will return a descriptive error message.
*   **Example**: Injecting `'` and receiving `You have an error in your SQL syntax; check the manual...`

### 2. Time-Based (Blind) Detection
Often, applications suppress error messages. In these cases, we use time-delay functions. If the server's response is delayed by the exact amount of time specified in our payload, we know the SQL command was executed.
*   **Example**: `1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--`

### 3. Boolean-Based (Blind) Detection
This involves asking the database true/false questions and observing changes in the page content or HTTP status codes.
*   **Example**: Comparing the response of `id=1 AND 1=1` (True) vs `id=1 AND 1=2` (False).

## Using the Tool

### Step 1: Preparation
Identify your target URL or list of URLs. Ensure you have permission to test the targets.

### Step 2: Running a Basic Scan
Scan a single URL with default settings:
```bash
python3 checker.py -u "http://example.com/product.php?id=10" -o my_report
```

### Step 3: Advanced Auditing
For more thorough testing, enable additional vectors when prompted:
- **Headers**: Tests `X-Forwarded-For`, `User-Agent`, and `Referer`.
- **Cookies**: Tests session identifiers and tracking cookies.
- **POST Data**: Tests form submissions.

### Step 4: Reviewing Results
Check the `outputs/` directory for detailed text logs of any detected vulnerabilities, or view the generated HTML report for a visual summary of the findings.

---
*Disclaimer: This tool is for educational and authorized security testing purposes only.*
