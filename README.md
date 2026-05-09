# SQL Injection Checker - Object-Oriented Version 2.0

## 📋 Overview

This is a completely refactored SQL Injection scanner, rebuilt with an object-oriented architecture. The new version offers improved code organization, maintainability, and extensibility, while retaining all functionalities of its procedural predecessor.

## ✨ Features

All core functionalities have been preserved and enhanced:

- [x] SQL Injection Scanning (Error-based, Time-based, Blind)
- [x] WAF Detection
- [x] Database Technology Detection
- [x] Web Page Crawling
- [x] User-Agent Rotation
- [x] Tor Support
- [x] Multithreading
- [x] HTML Report Generation
- [x] Statistics Collection
- [x] Custom Payload Handling
- [x] Configuration via `.env` file

## 🏗️ Architecture

The project follows a modular, object-oriented design for better organization and scalability.

```
sqlichecker/
├── checker.py                 # Main entry point
├── requirements.txt
├── src/
│   ├── config/
│   │   ├── .env              # Environment configuration
│   │   ├── payloads.txt      # Example SQL Injection payloads
│   │   └── websites-list.txt # Example list of target websites
│   │
│   ├── modules/              # Core object-oriented components
│   │   ├── __init__.py
│   │   ├── payload_manager.py      # Manages SQLi payloads
│   │   ├── request_handler.py      # Handles HTTP requests and sessions
│   │   ├── waf_detector.py         # Detects Web Application Firewalls
│   │   ├── vulnerability_detector.py  # Detects various SQLi vulnerabilities
│   │   ├── target_crawler.py       # Crawls websites to discover parameters
│   │   ├── report_generator.py     # Generates HTML reports
│   │   ├── statistics_collector.py # Collects and manages scan statistics
│   │   └── sqli_scanner.py         # Main scanner orchestration class
│   │
│   ├── utils/
│   │   ├── config_loader.py   # Loads configuration from .env
│   │   ├── file_manager.py    # Manages file operations
│   │   ├── logger.py          # Application logging
│   │   └── console-menager.py # Console UI management
│   │
│   ├── units/
│   │   └── menu.py            # Interactive menu logic
│   │
│   ├── logs/                  # Application logs
│   └── outputs/               # Scan results and reports
│
└── .beta/                     # Old procedural version (for reference)
```

## 🎯 Key Components

### 1. **SQLiScanner** (`sqli_scanner.py`)
The central orchestration class for the entire SQL Injection scanning process. It integrates and manages all other components.

```python
scanner = SQLiScanner(output_dir="outputs", threads=5, use_tor=False)
result = scanner.scan_url("http://example.com", payload_mode=3)
```

### 2. **PayloadManager** (`payload_manager.py`)
Responsible for managing and filtering SQL Injection payloads based on the detected database technology and selected mode.

- **Mode 1 (Basic):** Quick tests like `'`, `"`, `';--`
- **Mode 2 (Advanced):** Time-based and advanced payloads (e.g., `SLEEP`, `DELAY`)
- **Mode 3 (All):** Combination of Basic and Advanced payloads
- **Mode 4 (Custom):** Loads user-defined payloads from a file

### 3. **RequestHandler** (`request_handler.py`)
Handles HTTP sessions, manages User-Agent rotation, and provides Tor SOCKS5 proxy support.

- Automatic User-Agent rotation
- Payload injection into URL parameters
- Tor support (SOCKS5://127.0.0.1:9050)

### 4. **WafDetector** (`waf_detector.py`)
Detects Web Application Firewalls (WAFs) and identifies database technologies based on HTTP headers and response content.

Supported WAFs include:
- Cloudflare
- Sucuri
- Incapsula
- Akamai
- ModSecurity
- Wordfence
- Generic WAF signatures

### 5. **VulnerabilityDetector** (`vulnerability_detector.py`)
Provides comprehensive vulnerability detection capabilities:

- **Error-Based:** Detects SQL, PHP, and framework-specific error messages.
- **Time-Based:** Identifies delays in responses (e.g., `SLEEP`, `DELAY`, `PG_SLEEP`).
- **Blind SQLi:** Detects differences in response size or structural changes (>25% difference).
- **Server Errors:** Catches HTTP 500+ status codes.

### 6. **TargetCrawler** (`target_crawler.py`)
Discovers links and parameters on web pages.

- Extracts links (`href` attributes)
- Identifies hidden form fields
- Supports recursive crawling up to a specified depth

### 7. **ReportGenerator** (`report_generator.py`)
Generates interactive HTML reports using Charts.js for data visualization.

- Statistical charts
- Table of all detected vulnerabilities
- Summary of scan results

### 8. **StatisticsCollector** (`statistics_collector.py`)
Collects and manages various statistics during the scanning process.

- Tracks vulnerability types
- Records effective payloads
- Thread-safe operations using `Lock`

## 🚀 Usage

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-repo/sqlichecker.git
    cd sqlichecker
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Scanning Examples

- **Scan a single URL:**
    ```bash
    python checker.py -u http://example.com -o results.txt --threads 5
    ```
- **Scan a list of URLs from a file:**
    ```bash
    python checker.py -i urls.txt -o results.txt --threads 10
    ```
- **Scan with Tor proxy enabled:**
    ```bash
    python checker.py -i urls.txt -o results.txt --tor --threads 5
    ```
- **Crawl a website to discover parameters:**
    ```bash
    python checker.py -u http://example.com -o crawl_results.txt --crawl --depth 2
    ```

### Command-Line Options

| Option          | Description                                     |
| :-------------- | :---------------------------------------------- |
| `-i`, `--input` | Path to a file containing a list of URLs to scan |
| `-u`, `--url`   | A single URL to scan                            |
| `-o`, `--output`| Output file for results (required)              |
| `--tor`         | Use Tor SOCKS5 proxy                            |
| `--threads`     | Number of threads to use (1-50, default: 5)     |
| `--crawl`       | Enable website crawling to discover parameters  |
| `--depth`       | Crawling depth (default: 1)                     |
| `--help`        | Show program's help message and exit            |

### Payload Modes

When running the program, you will be prompted to select a payload mode:

1.  **Basic:** Fast tests using common SQLi characters (`'`, `"`, `';--`).
2.  **Advanced:** Time-based and more sophisticated payloads (e.g., `SLEEP`, `DELAY`).
3.  **All:** A combination of both Basic and Advanced payloads.
4.  **Custom:** Load payloads from a user-specified file (e.g., `src/config/payloads/custom.txt`).

### Configuration

Edit the `src/config/.env` file to customize connection settings and file paths:

```ini
[connection]
is_proxy=false
is_tor=false
tor_socks_port=9050

[lists]
websites_list_path=src/config/websites-list.txt
payloads_list_path=src/config/payloads.txt
OOB_DOMAIN=interact.sh # Domain for Out-of-Band (OOB) interactions
```

## 📊 Comparison: Procedural vs. Object-Oriented

### Procedural (Old Version)
-   1127 lines in a single file
-   Global functions, global state
-   Difficult to test
-   Many parameters passed to functions
-   High coupling between components

### Object-Oriented (New Version)
-   ~300 lines in the main file (`checker.py`)
-   Functionalities separated into distinct classes (8 modules)
-   Easy to test (each class can be tested independently)
-   Fewer parameters (state managed within objects)
-   Loose coupling - independent components
-   Easier extensibility

## 🧩 Extensibility

The object-oriented architecture makes it easy to extend the scanner's capabilities:

### Adding a New WAF Detector

To add a new WAF, simply update the `WAF_SIGNATURES` dictionary in `waf_detector.py`:

```python
# In waf_detector.py, add to WAF_SIGNATURES:
"MyWAF": {
    "headers": ["Server: MyWAF"],
    "status_codes":,
    "body_keywords": ["MyWAF"]
}
```

### Adding a New Vulnerability Type

To implement a new vulnerability detection method, add it to `vulnerability_detector.py`:

```python
# In vulnerability_detector.py, add a new method:
def check_custom_vulnerability(self, response_text):
    # Your custom detection logic here
    return is_vulnerable, method_info
```

## 📝 Output

### Result Files
-   `outputs/results.txt`: A list of discovered vulnerable URLs.
-   `outputs/results.html`: An interactive HTML report (if `--gen-html` option is used).
-   `outputs/VULN_[domain].txt`: Detailed vulnerability information for specific domains.

### HTML Report
-   Charts.js-powered statistical graphs.
-   A table listing all detected vulnerabilities.
-   Summaries of vulnerability types and effective payloads.

## 🔐 Security Considerations

-   **HTTPS Support:** Handles HTTPS connections, with an option to disable SSL verification for self-signed certificates.
-   **Tor Integration:** Supports Tor via SOCKS5 proxy for anonymized scanning.
-   **User-Agent Rotation:** Automatically rotates User-Agents to mimic different browsers and avoid detection.
-   **Rate-Limit Detection:** Includes mechanisms to detect and handle HTTP 429 (Too Many Requests) responses.
-   **Smart-Delay System:** Dynamically adjusts request delays to prevent overwhelming target servers.

## 📚 Dependencies

The following Python packages are required:

```
requests>=2.28.0
urllib3>=1.26.0
colorama>=0.4.6
psutil>=5.9.0
python-dotenv>=0.20.0
```

## 🐛 Troubleshooting

-   **"Config file not found"**: Ensure `src/config/.env` exists and is correctly configured.
-   **Timeout errors**: Increase the request timeout using `--timeout 10` (or a higher value).
-   **Tor not working**: Verify that your Tor service is running and accessible on the configured SOCKS5 port (default: 9050). You can start Tor with `tor --socks-port 9050`.

## 📄 License

This tool is intended for security research purposes. It should only be used for educational purposes and authorized penetration testing.

## 👨‍💻 Authors

-   Object-Oriented Refactoring: 2026
-   Original Procedural Version: [Original Author/Year, if known]

---

**Version**: 2.0 Object-Oriented
**Date**: May 2026
**Status**: Actively Maintained