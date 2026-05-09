
import os
from dotenv import load_dotenv
import logging
from colorama import init, Fore, Style

init(autoreset=True)

class ConfigLoader:
    def __init__(self, env_path='src/config/.env'):
        self.env_path = env_path

    def load_env(self):
        if not os.path.exists(self.env_path):
            print(Fore.RED + Style.BRIGHT + f"[ERROR] Config file not found: {self.env_path}")
            return False
        load_dotenv(self.env_path)
        print(Fore.GREEN + Style.BRIGHT + f"[OK] Loaded environment variables from {self.env_path}")
        return True
    def check_required_files(self):
        required_files = ['src/config/.env','src/units/menu.py','src/utils/console-menager.py','src/utils/config_loader.py','src/utils/file_manager.py','src/utils/logger.py']
        missing_files = [f for f in required_files if not os.path.exists(f)]
        if missing_files:
            print(Fore.RED + Style.BRIGHT + f"[ERROR] Missing required files: {', '.join(missing_files)}")
            return False
        print(Fore.GREEN + Style.BRIGHT + "[OK] All required files are present.")
        return True
    def check_required_config_vars(self):
        required_vars = ['websites_list_path']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            print(Fore.RED + Style.BRIGHT + f"[ERROR] Missing required config variables: {', '.join(missing_vars)}")
            return False
        print(Fore.GREEN + Style.BRIGHT + "[OK] All required config variables are set.")
        return True
    def validate_config(self):
        if not self.check_required_files():
            return False
        if not self.load_env():
            return False
        if not self.check_required_config_vars():
            return False
        print(Fore.CYAN + Style.BRIGHT + "[SUCCESS] Configuration validation successful.")
        return True
    
    def load_tor_connection(self):
        tor_proxy = os.getenv('is_tor')
        if not tor_proxy or tor_proxy == 'NULL' or tor_proxy.lower() == 'false':
            print(Fore.YELLOW + Style.BRIGHT + "[WARNING] Tor proxy not configured. Skipping Tor connection.")
            return None
        tor_socks_port = os.getenv('tor_socks_port', '9050')