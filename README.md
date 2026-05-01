# SQLi Auditor 

## It's Beta Version! 

You see a bug? Text me :-0

A simple, multi-threaded SQL Injection vulnerability scanner designed for security researchers and penetration testers. This tool automates the process of discovering SQLi vulnerabilities across multiple vectors including URL parameters, HTTP headers, cookies, and POST data.

## Features

- **Multi-Vector Scanning**: Support for GET parameters, POST data, HTTP Headers, and Cookies.
- **Intelligent Detection**: Recognizes Error-Based, Time-Based, and Blind (Size-Based) SQL injection.
- **WAF & Tech Fingerprinting**: Automatically detects WAFs (Cloudflare, Akamai, etc.) and server technologies (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) to optimize payloads.
- **Built-in Crawler**: Discover parameterized links and hidden form fields within a target domain.
- **Smart Delay System**: Automatically adjusts request timing when rate-limiting (429) is detected.
- **Tor Support**: Routing traffic through SOCKS5 proxy for anonymity.
- **Advanced Reporting**: Generates interactive HTML reports with statistics and charts.

## Installation

```bash
git clone https://github.com/SQLi_checker-beta-v.1.0/sqlichecker.git
cd sqlichecker
pip install -r requirements.txt
```
*Note: Requires `requests`, `psutil`, `colorama`, and `urllib3`.*

## Usage

### Basic Scan (Single URL)
```bash
python checker.py -u "http://example.com/index.php?id=1" -o results.txt
```

### Bulk Scan (URL List)
```bash
python checker.py -i targets.txt -o output.txt --threads 10
```

### Crawl & Scan
```bash
python checker.py -u "http://example.com" --crawl --depth 2 -o discovered_links.txt
```

## Parameters

| Parameter | Description |
| :--- | :--- |
| `-i, --input` | Path to a file containing a list of URLs to scan. |
| `-u, --url` | A single URL to perform a full scan on. |
| `-o, --output` | Filename for saving identified vulnerabilities. |
| `--threads` | Number of concurrent threads (1-50, default: 1). |
| `--delay` | Fixed delay between requests in seconds. |
| `--crawl` | Enables the crawler to find links before scanning. |
| `--depth` | Maximum crawling depth (default: 1). |
| `--tor` | Routes requests through the Tor network (127.0.0.1:9050). |
| `--random-agent` | Uses a random User-Agent for each request. |

## Interactive Menu
Upon launching, the tool will prompt for:
1. **Timeout**: Connection timeout per request.
2. **Injection Vectors**: Option to enable scanning for Headers, Cookies, and POST methods.
3. **Payload Modes**: Select between Basic, Advanced, All, or Custom payload files.
4. **HTML Report**: Choose whether to generate a visual audit report.

## Disclaimer
This tool is for educational and authorized security testing purposes only. Usage against targets without prior consent is illegal.


## Test IT 

- **I am left  example list in test_list.txt if someone need to check it. just run python3 checker.py -i test_list.txt -o results.txt --random-agent --threads (1-10 its recomended)**

## Adding Payloads Files

- **If you would to add more payloads just put .txt file to payloads/ folder script will detect it and You will see it in menu**