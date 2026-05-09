"""
TargetCrawler - Crawlowanie stron w poszukiwaniu parametrów
"""

import re
import requests
from typing import Set, Tuple, Dict
from urllib.parse import urljoin, urlparse, urlencode


class TargetCrawler:
    """Crawlowanie stron w poszukiwaniu linków i parametrów"""
    
    def __init__(self, session: requests.Session, max_retries: int = 3):
        """
        Inicjalizacja crawlera
        
        Args:
            session: Sesja requests do używania
            max_retries: Maksymalna liczba prób w wypadku błędu
        """
        self.session = session
        self.max_retries = max_retries
    
    def crawl_links(self, url: str, headers: Dict = None, timeout: int = 5) -> Tuple[Set[str], Set[str]]:
        """
        Przeszukuje stronę w poszukiwaniu linków i parametrów
        
        Args:
            url: URL do przeszukania
            headers: Nagłówki HTTP
            timeout: Timeout żądania
        
        Returns:
            Tuple (wszystkie_linki, linki_z_parametrami)
        """
        all_links = set()
        parameterized = set()
        
        try:
            response = self.session.get(url, headers=headers, timeout=timeout, verify=False)
            if response.status_code != 200:
                return all_links, parameterized
            
            html = response.text
            base_domain = urlparse(url).netloc
            
            # 1. Wyciąg linków z href
            all_links, parameterized = self._extract_href_links(html, url, base_domain, all_links, parameterized)
            
            # 2. Odkrycie ukrytych pól w formularzach
            all_links, parameterized = self._extract_form_fields(html, url, base_domain, all_links, parameterized)
            
            return all_links, parameterized
        
        except Exception as e:
            print(f"[ERROR] Błąd podczas crawlowania {url}: {e}")
            return all_links, parameterized
    
    def _extract_href_links(self, html: str, base_url: str, base_domain: str, 
                           all_links: Set[str], parameterized: Set[str]) -> Tuple[Set[str], Set[str]]:
        """Wyciąga linki z href"""
        links = re.findall(r'href=["\'](.[^"\' >]+)["\']', html)
        
        for link in links:
            full_url = urljoin(base_url, link).split('#')[0]
            parsed_full = urlparse(full_url)
            
            if parsed_full.netloc == base_domain:
                all_links.add(full_url)
                
                if '?' in full_url and '=' in full_url:
                    parameterized.add(full_url)
        
        return all_links, parameterized
    
    def _extract_form_fields(self, html: str, base_url: str, base_domain: str,
                            all_links: Set[str], parameterized: Set[str]) -> Tuple[Set[str], Set[str]]:
        """Wyciąga ukryte pola z formularzy"""
        forms = re.finditer(r'<form\b[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        
        for form_match in forms:
            content = form_match.group(1)
            opening_tag = html[max(0, form_match.start()):form_match.start() + html[form_match.start():].find('>')]
            
            action_match = re.search(r'action=["\']([^"\']*)["\']', opening_tag, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            
            # Wyszukiwanie ukrytych input fields
            hidden_inputs = re.findall(
                r'<input\b[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                content, re.IGNORECASE
            )
            
            if not hidden_inputs:
                hidden_inputs = re.findall(
                    r'<input\b[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\'][^>]*type=["\']hidden["\']',
                    content, re.IGNORECASE
                )
            
            if hidden_inputs:
                params = {name: val for name, val in hidden_inputs}
                target_url = urljoin(base_url, action)
                sep = '&' if '?' in target_url else '?'
                surface_url = f"{target_url}{sep}{urlencode(params)}"
                
                if urlparse(surface_url).netloc == base_domain:
                    parameterized.add(surface_url)
                    print(f"[INFO] Discovered hidden fields in form: {action}")
        
        return all_links, parameterized
    
    def crawl_recursive(self, start_urls: list, max_depth: int = 1, max_workers: int = 1) -> Set[str]:
        """
        Crawluje strony rekurencyjnie do określonej głębokości
        
        Args:
            start_urls: Lista początkowych URLi
            max_depth: Maksymalna głębokość crawlowania
            max_workers: Liczba wątków do crawlowania
        
        Returns:
            Set wszystkich znalezionych linków z parametrami
        """
        all_parameterized = set()
        visited = set()
        to_visit = set(start_urls)
        
        for depth in range(1, max_depth + 1):
            if not to_visit:
                break
            
            print(f"[INFO] Depth {depth}/{max_depth}. Links to check: {len(to_visit)}")
            
            next_to_visit = set()
            
            for url in list(to_visit):
                if url in visited:
                    continue
                
                visited.add(url)
                discovered_links, discovered_parameterized = self.crawl_links(url)
                
                next_to_visit.update(discovered_links)
                all_parameterized.update(discovered_parameterized)
                print(f"[OK] {url}: Found {len(discovered_parameterized)} parameters")
            
            to_visit = next_to_visit - visited
        
        return all_parameterized
