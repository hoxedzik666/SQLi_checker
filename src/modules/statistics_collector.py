"""
StatisticsCollector (English Version)
"""

from threading import Lock
from typing import Dict

class StatisticsCollector:
    def __init__(self):
        self.vulnerability_types = {}
        self.effective_payloads = {}
        self.vulnerabilities_data = []
        self.lock = Lock()
    
    def add_vulnerability(self, data: Dict) -> None:
        with self.lock: self.vulnerabilities_data.append(data)
    
    def record_vulnerability_type(self, v_type: str, count: int = 1) -> None:
        with self.lock: self.vulnerability_types[v_type] = self.vulnerability_types.get(v_type, 0) + count
    
    def record_effective_payload(self, payload: str, count: int = 1) -> None:
        with self.lock: self.effective_payloads[payload] = self.effective_payloads.get(payload, 0) + count

    def get_vulnerability_types(self): return self.vulnerability_types.copy()
    def get_effective_payloads(self): return self.effective_payloads.copy()
    def get_vulnerabilities_data(self): return self.vulnerabilities_data.copy()

    def print_summary(self) -> None:
        from colorama import Fore, Style
        with self.lock:
            if not self.vulnerabilities_data:
                print(Fore.YELLOW + "\n[!] No vulnerabilities detected - no statistics available." + Style.RESET_ALL)
                return
            
            print(Fore.CYAN + Style.BRIGHT + "\n" + "═"*60)
            print(Fore.CYAN + Style.BRIGHT + "║" + " "*18 + "STATISTICS SUMMARY" + " "*22 + "║")
            print(Fore.CYAN + Style.BRIGHT + "═"*60)
            
            print(Fore.YELLOW + f"\n[+] Total Vulnerabilities: {Fore.GREEN}{len(self.vulnerabilities_data)}{Style.RESET_ALL}")
            
            print(Fore.YELLOW + "\n[+] Top Vulnerability Types:")
            sorted_types = sorted(self.vulnerability_types.items(), key=lambda x: x[1], reverse=True)[:5]
            for v_type, count in sorted_types:
                print(f"    - {v_type:30} : {Fore.GREEN}{count}{Style.RESET_ALL} hits")
            
            print(Fore.YELLOW + "\n[+] Most Effective Payloads:")
            sorted_payloads = sorted(self.effective_payloads.items(), key=lambda x: x[1], reverse=True)[:5]
            for payload, count in sorted_payloads:
                clean_p = payload.replace('\n', ' ').strip()
                print(f"    - {clean_p[:50]:50} : {Fore.GREEN}{count}{Style.RESET_ALL} successes")
            
            print(Fore.CYAN + "\n" + "═"*60 + Style.RESET_ALL)