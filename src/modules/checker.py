#!/usr/bin/env python3
"""
SQLi Auditor - Professional SQL Injection Audit Tool
Object-oriented implementation v2.0 (English Version)
"""

import sys
import os
import argparse
import time
import random
from typing import Dict, Tuple
from pathlib import Path

# Add modules path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from colorama import Fore, Style, init
from modules import SQLiScanner, PayloadManager, ReportGenerator
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)

def print_banner():
    """Displays application banner with a special character wall"""
    wall = "#!@)*&^%" * 8
    banner = f"""{Fore.CYAN}{Style.BRIGHT}
{wall}
#!                                                              %
#!              {Fore.YELLOW}C H A R L I 3 P R O J E C T S{Fore.CYAN}                   !
#!                                                              %
#!      {Fore.WHITE}GitHub:   https://github.com/charli3vintage77{Fore.CYAN}           @
#)      {Fore.WHITE}Telegram: @charli3vintage77{Fore.CYAN}                             #
#!                                                              %
{wall}{Style.RESET_ALL}"""
    print(banner)

def validate_args(args):
    """Argument validation"""
    if not args.input and not args.url:
        print(Fore.RED + "[-] You must provide an input file (-i) or a single URL (-u)!" + Style.RESET_ALL)
        return False
    
    if args.threads < 1 or args.threads > 50:
        print(Fore.RED + "[-] Thread count must be between 1 and 50" + Style.RESET_ALL)
        return False
    
    return True

def get_user_input_menu():
    """Interactive menu - scanning options"""
    print(Fore.YELLOW + "\n=== SCANNING OPTIONS ===" + Style.RESET_ALL)
    
    # Timeout
    t_in = input(Fore.YELLOW + "1. Timeout (seconds, default 5): " + Style.RESET_ALL)
    timeout = int(t_in) if t_in else 5
    
    # Payload delay
    d_in = input(Fore.YELLOW + "2. Delay between payloads (seconds, default 0): " + Style.RESET_ALL)
    payload_delay = float(d_in) if d_in else 0
    
    # User-Agent
    print(Fore.YELLOW + "\n3. User-Agent:" + Style.RESET_ALL)
    print("   [1] Chrome  [2] iPhone  [3] Firefox  [R] Random")
    ua_choice = input(Fore.YELLOW + "Choice: " + Style.RESET_ALL).upper()
    random_ua_mode = ua_choice == 'R'
    
    # UA rotation interval
    ua_rotation_interval = 5
    if random_ua_mode:
        rot_in = input(Fore.YELLOW + "4. Rotation interval (every N requests, default 5): " + Style.RESET_ALL)
        ua_rotation_interval = int(rot_in) if rot_in else 5
    
    # Injection options
    print(Fore.RED + Style.BRIGHT + "\n[ADVANCED] INJECTION VECTORS (Increases scan time!):" + Style.RESET_ALL)
    scan_headers = input(Fore.YELLOW + "5. Scan Headers? (y/n): " + Style.RESET_ALL).lower() == 'y'
    scan_cookies = input(Fore.YELLOW + "6. Scan Cookies? (y/n): " + Style.RESET_ALL).lower() == 'y'
    scan_post = input(Fore.YELLOW + "7. Scan POST method (JSON/Form)? (y/n): " + Style.RESET_ALL).lower() == 'y'
    
    # HTML Report
    gen_html = input(Fore.YELLOW + "\n8. Generate interactive HTML report? (y/n): " + Style.RESET_ALL).lower() == 'y'
    
    # SQLi mode
    print(Fore.YELLOW + "\n9. Payload mode:" + Style.RESET_ALL)
    print("   [1] Basic  [2] Advanced  [3] All  [4] CUSTOM FILE")
    sqli_mode = int(input(Fore.YELLOW + "Choice (default 3): " + Style.RESET_ALL) or "3")
    
    custom_payloads = []
    if sqli_mode == 4:
        payload_manager = PayloadManager(payloads_dir='payloads')
        payload_files = payload_manager.get_payload_file_list()
        
        if not payload_files:
            print(Fore.RED + "[-] No payload files found in 'payloads/' directory!")
            sqli_mode = 3
        else:
            print(Fore.CYAN + "\n=== AVAILABLE PAYLOADS ===" + Style.RESET_ALL)
            for idx, (filename, _) in enumerate(payload_files, 1):
                print(f"{Fore.YELLOW}[{idx}]{Style.RESET_ALL} {filename}")
            
            try:
                choice = int(input(Fore.GREEN + "\nSelect number: " + Style.RESET_ALL)) - 1
                if 0 <= choice < len(payload_files):
                    _, filepath = payload_files[choice]
                    custom_payloads = payload_manager.load_payloads_from_file(filepath)
                    print(Fore.GREEN + f"[+] Loaded {len(custom_payloads)} payloads" + Style.RESET_ALL)
                else:
                    sqli_mode = 3
            except ValueError:
                sqli_mode = 3
    
    return {
        "timeout": timeout, "payload_delay": payload_delay, "random_ua": random_ua_mode,
        "ua_rotation_interval": ua_rotation_interval, "scan_headers": scan_headers,
        "scan_cookies": scan_cookies, "scan_post": scan_post, "gen_html": gen_html,
        "sqli_mode": sqli_mode, "custom_payloads": custom_payloads
    }

def load_urls(args) -> list:
    if args.url: return [args.url]
    try:
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]
        print(Fore.GREEN + f"[+] Loaded {len(urls)} URLs" + Style.RESET_ALL)
        return urls
    except FileNotFoundError:
        print(Fore.RED + f"[-] File {args.input} not found!" + Style.RESET_ALL)
        sys.exit(1)

def _scan_single_url_task(scanner: SQLiScanner, thread_id: int, url: str, options: Dict) -> Dict:
    return scanner.scan_url(
        url, payload_mode=options["sqli_mode"], custom_payloads=options["custom_payloads"],
        scan_headers=options["scan_headers"], scan_cookies=options["scan_cookies"],
        scan_post=options["scan_post"], random_ua=options["random_ua"],
        ua_rotation_interval=options["ua_rotation_interval"], thread_id=thread_id,
        expected_tests=options.get("expected_per_url", 0)
    )

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Auditor - Object Oriented")
    parser.add_argument("-i", "--input", help="File with URL list")
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-o", "--output", required=True, help="Output filename")
    parser.add_argument("--tor", action="store_true", help="Use Tor SOCKS5")
    parser.add_argument("--threads", type=int, default=5, help="Thread count (1-50)")
    parser.add_argument("--crawl", action="store_true", help="Crawl site for parameters")
    parser.add_argument("--depth", type=int, default=1, help="Crawling depth")
    
    args = parser.parse_args()
    if not validate_args(args): sys.exit(1)
    
    print_banner()
    options = get_user_input_menu()
    
    if args.tor:
        print(Fore.YELLOW + "[*] Testing Tor connection..." + Style.RESET_ALL)
        temp_scanner = SQLiScanner(use_tor=True)
        success, ip = temp_scanner.request_handler.test_tor_connection()
        if success:
            print(Fore.GREEN + f"[✓] Tor Connected: {ip}" + Style.RESET_ALL)
        else:
            if input(Fore.YELLOW + "[?] Continue without Tor? (y/n): " + Style.RESET_ALL).lower() != 'y':
                sys.exit(1)
            args.tor = False
    
    urls = load_urls(args)
    if args.crawl:
        print(Fore.CYAN + f"\n[*] Starting Crawler..." + Style.RESET_ALL)
        scanner_crawl = SQLiScanner(output_dir="outputs", timeout=options["timeout"], threads=1, use_tor=args.tor)
        discovered = scanner_crawl.crawl_and_discover(urls, args.depth)
        if discovered:
            with open(os.path.join("outputs", args.output), 'w') as f:
                for u in sorted(discovered): f.write(u + "\n")
            print(Fore.GREEN + f"[✓] Discovered {len(discovered)} links.")
        sys.exit(0)

    payload_manager = PayloadManager()
    payload_count = len(payload_manager.get_payloads_by_mode(options["sqli_mode"], custom_payloads=options["custom_payloads"])) or 1
    
    multiplier = 1
    if options["scan_headers"]: multiplier += len(SQLiScanner.VULNERABLE_HEADERS)
    if options["scan_cookies"]: multiplier += 3
    if options["scan_post"]: multiplier += 1

    expected_per_url = (payload_count * multiplier) + 1
    options["expected_per_url"] = expected_per_url

    scanner = SQLiScanner(output_dir="outputs/results", timeout=options["timeout"], threads=args.threads, use_tor=args.tor)
    scanner.global_delay = options["payload_delay"]
    scanner.total_queries = len(urls) * expected_per_url

    os.system('clear' if os.name != 'nt' else 'cls')
    print(f"{Fore.CYAN}{Style.BRIGHT}  SQLi AUDITOR v2.0 - ACTIVE SESSION{Style.RESET_ALL}")
    print(f"  {'─'*60}")
    print(f"  {Fore.YELLOW}TARGETS: {Fore.WHITE}{len(urls)} URLs  {Fore.YELLOW}THREADS: {Fore.WHITE}{args.threads}")
    print(f"  {Fore.YELLOW}VECTORS: {Fore.WHITE}Header:{options['scan_headers']} Cookie:{options['scan_cookies']} POST:{options['scan_post']}")
    print(f"  {Fore.YELLOW}TIMEOUT: {Fore.WHITE}{options['timeout']}s  {Fore.YELLOW}DELAY: {Fore.WHITE}{options['payload_delay']}s")
    print(f"  {'─'*60}\n\n")
    print(f"  {Fore.CYAN}{Style.BRIGHT}ACTIVE THREADS STATUS:{Style.RESET_ALL}")
    print(f"  {Fore.BLUE}{'═'*80}{Style.RESET_ALL}")

    # Initialize the dynamic UI area (progress, threads, event log)
    scanner._initialize_ui_area()
    scanner.start_ui()


    scanned_count = 0
    vulnerable_count = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(_scan_single_url_task, scanner, i % args.threads, url, options): url for i, url in enumerate(urls)}
        for future in as_completed(futures):
            try:
                res = future.result()
                scanned_count += 1
                if res["sqli_found"]: vulnerable_count += res["vulnerabilities_count"]
            except Exception as e:
                scanned_count += 1
                scanner._update_thread_ui(0, f"{Fore.RED}[CRITICAL] Error {futures[future]}: {str(e)[:40]}")

    scanner.stop_ui()

    sys.stdout.write(f"\033[{SQLiScanner.HEADER_HEIGHT + args.threads + scanner.event_log_max + 2};1H")
    print(Fore.CYAN + Style.BRIGHT + "\n" + "═"*60)
    print(Fore.CYAN + Style.BRIGHT + "║" + " "*14 + "SCANNING COMPLETED" + " "*26 + "║")
    print(Fore.CYAN + Style.BRIGHT + "═"*60)
    print(Fore.GREEN + f"\n[✓] Scanned: {scanned_count} URLs")
    print(Fore.GREEN + f"[✓] Vulnerabilities found: {vulnerable_count}")
    
    scanner.statistics.print_summary()
    
    if options["gen_html"]:
        report_gen = ReportGenerator("outputs")
        html_path = os.path.join("outputs", args.output.rsplit('.', 1)[0] + ".html")
        report_gen.generate_html_report(html_path, scanner.statistics.get_vulnerabilities_data(),
                                       scanner.statistics.get_vulnerability_types(),
                                       scanner.statistics.get_effective_payloads())
    
    print(Fore.YELLOW + f"\n[*] Reports saved in: outputs/" + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted by user")
        sys.exit(0)