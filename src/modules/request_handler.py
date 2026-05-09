"""
RequestHandler - Obsługa sesji HTTP, User-Agent rotation, Tor
"""

import requests
import os
import random
import time
import logging
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RequestHandler:
    """Zarządzanie sesją HTTP i parametrami żądań"""
    
    USER_AGENTS = {
        "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "firefox": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    }
    
    def __init__(self, use_tor: bool = False, timeout: int = 5, max_retries: int = 3, backoff_factor: float = 1.0):
        """
        Inicjalizacja obsługi żądań
        
        Args:
            use_tor: Czy używać Tor SOCKS5
            timeout: Timeout dla żądań (sekundy)
            max_retries: Maksymalna liczba prób ponowienia żądania
            backoff_factor: Współczynnik opóźnienia dla wykładniczego czasu oczekiwania
        """
        self.timeout = timeout
        self.use_tor = use_tor
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = self._create_session()
        self.request_count = 0
        self.current_ua = self.get_random_user_agent()
        self.urlparse = urlparse
        self.parse_qs = parse_qs
        self._setup_logger()

    def _setup_logger(self):
        """Konfiguruje system logowania do pliku debug.log"""
        log_dir = os.path.join(os.getcwd(), "logs")
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError:
                pass

        self.logger = logging.getLogger("sqlichecker.http")
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            file_path = os.path.join(log_dir, "debug.log")
            # Używamy FileHandler z kodowaniem utf-8 dla bezpieczeństwa
            handler = logging.FileHandler(file_path, encoding='utf-8')
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _create_session(self) -> requests.Session:
        """Tworzy sesję HTTP z konfiguracją"""
        session = requests.Session()
        session.verify = False
        
        # Konfiguracja strategii retry (exponential backoff)
        # Algorytm: backoff_factor * (2 ** (number_of_retries - 1))
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        
        if self.use_tor:
            session.proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def get_random_user_agent(self) -> str:
        """Zwraca losowy User-Agent"""
        return random.choice(list(self.USER_AGENTS.values()))
    
    def get_user_agent(self, agent_type: str = "chrome") -> str:
        """
        Zwraca User-Agent dla danego typu
        
        Args:
            agent_type: Typ UA (chrome, iphone, firefox)
        
        Returns:
            String User-Agent
        """
        return self.USER_AGENTS.get(agent_type, self.USER_AGENTS["chrome"])
    
    def rotate_user_agent(self, request_count: int, rotation_interval: int = 5, random_mode: bool = False) -> str:
        """
        Rotuje User-Agent co N żądań
        
        Args:
            request_count: Licznik żądań
            rotation_interval: Co ile żądań zmienić UA
            random_mode: Czy używać losowe UA
        
        Returns:
            User-Agent string
        """
        if random_mode and request_count % rotation_interval == 0:
            self.current_ua = self.get_random_user_agent()
        
        return self.current_ua
    
    def inject_payload_to_url(self, url: str, payload: str) -> list:
        """
        Wstrzykuje payload do parametrów URL
        
        Args:
            url: URL do modyfikacji
            payload: Payload do wstrzykiwania
        
        Returns:
            Lista tuple (nowy_url, nazwa_parametru)
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return [(f"{url}?id={payload}", "id_added")]
        
        injected_urls = []
        for key in params:
            new_params = params.copy()
            new_params[key] = [f"{val}{payload}" for val in params[key]]
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            injected_urls.append((new_url, key))
        
        return injected_urls
    
    def get(self, url: str, headers: Optional[Dict] = None, cookies: Optional[Dict] = None, **kwargs) -> requests.Response:
        """
        Wykonuje GET request
        
        Args:
            url: URL
            headers: Nagłówki HTTP
            cookies: Cookies
        
        Returns:
            Response object
        """
        if headers is None:
            headers = {"User-Agent": self.current_ua}
        
        try:
            response = self.session.get(url, headers=headers, cookies=cookies, timeout=self.timeout + 7, verify=False, **kwargs)
            if response.status_code >= 400:
                self.logger.warning(f"HTTP {response.status_code} | GET | {url}")
            return response
        except Exception as e:
            self.logger.error(f"EXCEPTION | GET | {url} | {str(e)}")
            raise
    
    def post(self, url: str, data: Dict = None, json: Dict = None, headers: Optional[Dict] = None, cookies: Optional[Dict] = None, **kwargs) -> requests.Response:
        """
        Wykonuje POST request
        
        Args:
            url: URL
            data: Dane POST (form-encoded)
            json: Dane POST (JSON)
            headers: Nagłówki HTTP
            cookies: Cookies
        
        Returns:
            Response object
        """
        if headers is None:
            headers = {"User-Agent": self.current_ua}
        
        try:
            response = self.session.post(url, data=data, json=json, headers=headers, cookies=cookies, timeout=self.timeout + 7, verify=False, **kwargs)
            if response.status_code >= 400:
                self.logger.warning(f"HTTP {response.status_code} | POST | {url}")
            return response
        except Exception as e:
            self.logger.error(f"EXCEPTION | POST | {url} | {str(e)}")
            raise
    
    def test_tor_connection(self) -> Tuple[bool, Optional[str]]:
        """
        Testuje połączenie z Tor
        
        Returns:
            Tuple (success, ip_address)
        """
        try:
            response = self.get('http://check.torproject.org/api/ip', timeout=3)
            data = response.json()
            if data.get('is_tor'):
                return True, data.get('ip')
        except:
            try:
                response = self.get('http://icanhazip.com', timeout=5)
                if response.status_code == 200:
                    return True, response.text.strip()
            except:
                pass
        
        return False, None
    
    def get_domain(self, url: str) -> str:
        """Wyciąga domenę z URL"""
        try:
            netloc = urlparse(url).netloc
            return netloc if netloc else url.split('/')[0]
        except:
            return "unknown"
    
    def prepare_url(self, url: str) -> str:
        """Przygotowuje URL (dodaje http:// jeśli potrzeba)"""
        if not url.startswith(('http://', 'https://')):
            return f"http://{url}"
        return url
