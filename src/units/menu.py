import os
from colorama import Fore, Style
from modules.payload_manager import PayloadManager

def get_user_input_menu():
    """Wyświetla menu interaktywne i zbiera opcje od użytkownika"""
    print(Fore.YELLOW + "\n" + "═"*45)
    print(Fore.YELLOW + "║" + Style.BRIGHT + "       KONFIGURACJA AUDYTU SQLi      " + Style.RESET_ALL + Fore.YELLOW + "║")
    print(Fore.YELLOW + "═"*45 + Style.RESET_ALL)
    
    # Timeout
    t_in = input(f"{Fore.CYAN}  [1] Timeout (sekundy, domyślnie 5): {Style.RESET_ALL}")
    timeout = int(t_in) if t_in else 5
    
    # Opóźnienie
    d_in = input(f"{Fore.CYAN}  [2] Opóźnienie między żądaniami (sekundy): {Style.RESET_ALL}")
    payload_delay = float(d_in) if d_in else 0.0
    
    # User-Agent
    print(f"\n{Fore.YELLOW}  [3] Wybór User-Agent:{Style.RESET_ALL}")
    print("      [1] Chrome  [2] iPhone  [3] Firefox  [L] Losowy")
    ua_choice = input(f"{Fore.CYAN}      Wybór: {Style.RESET_ALL}").upper()
    random_ua_mode = ua_choice == 'L'
    
    # Opcje wstrzykiwania
    print(f"\n{Fore.RED}{Style.BRIGHT}  [!] WEKTORY ATAKU (Wydłużają czas skanu):{Style.RESET_ALL}")
    scan_headers = input(f"{Fore.CYAN}      Skanować nagłówki HTTP? (t/n): {Style.RESET_ALL}").lower() == 't'
    scan_cookies = input(f"{Fore.CYAN}      Skanować ciasteczka? (t/n): {Style.RESET_ALL}").lower() == 't'
    scan_post = input(f"{Fore.CYAN}      Skanować dane POST? (t/n): {Style.RESET_ALL}").lower() == 't'
    
    # Raport HTML
    gen_html = input(f"\n{Fore.CYAN}  [4] Wygenerować raport HTML? (t/n): {Style.RESET_ALL}").lower() == 't'
    
    # Tryb payloadów
    print(f"\n{Fore.YELLOW}  [5] Tryb Payloadów:{Style.RESET_ALL}")
    print("      [1] Szybki (Basic)  [2] Zaawansowany (Time-based)  [3] Pełny (All)  [4] WŁASNY PLIK")
    sqli_mode = int(input(f"{Fore.CYAN}      Wybór (1-4): {Style.RESET_ALL}") or "3")
    
    custom_payloads = []
    if sqli_mode == 4:
        payload_manager = PayloadManager(payloads_dir='payloads')
        payload_files = payload_manager.get_payload_file_list()
        
        if not payload_files:
            print(Fore.RED + "      [-] Folder 'payloads/' jest pusty! Używam trybu Pełnego." + Style.RESET_ALL)
            sqli_mode = 3
        else:
            print(f"\n{Fore.CYAN}      Znalezione pliki w payloads/:{Style.RESET_ALL}")
            for idx, (filename, _) in enumerate(payload_files, 1):
                print(f"      [{idx}] {filename}")
            
            try:
                choice = int(input(f"{Fore.GREEN}      Wybierz numer pliku: {Style.RESET_ALL}")) - 1
                if 0 <= choice < len(payload_files):
                    _, filepath = payload_files[choice]
                    custom_payloads = payload_manager.load_payloads_from_file(filepath)
                    print(Fore.GREEN + f"      [+] Załadowano {len(custom_payloads)} payloadów." + Style.RESET_ALL)
                else:
                    sqli_mode = 3
            except ValueError:
                sqli_mode = 3
                
    print(Fore.YELLOW + "═"*45 + "\n" + Style.RESET_ALL)
    
    return {
        "timeout": timeout,
        "payload_delay": payload_delay,
        "random_ua": random_ua_mode,
        "ua_rotation_interval": 5,
        "scan_headers": scan_headers,
        "scan_cookies": scan_cookies,
        "scan_post": scan_post,
        "gen_html": gen_html,
        "sqli_mode": sqli_mode,
        "custom_payloads": custom_payloads
    }