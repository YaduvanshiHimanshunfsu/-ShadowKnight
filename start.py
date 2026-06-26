import os
import sys
import subprocess
import time
import logging
from pathlib import Path
from datetime import datetime

# -----------------------------------------------------------------------------
# 1. SETUP LOGGING FIRST (To capture everything)
# -----------------------------------------------------------------------------
def setup_logging():
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / "shadowknight_action.log"
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - [%(levelname)s] - %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
        ]
    )
    return logging.getLogger("ShadowKnightCLI")

logger = setup_logging()

# -----------------------------------------------------------------------------
# 2. DEPENDENCY AUTO-INSTALLER
# -----------------------------------------------------------------------------
def check_and_install_dependencies():
    logger.info("Checking dependencies...")
    try:
        import colorama
        import psutil
        import dotenv
    except ImportError:
        print("\n[!] Missing core dependencies detected.")
        choice = input("[?] Would you like to install them automatically? (Y/n): ").strip().lower()
        if choice in ['', 'y', 'yes']:
            print("[*] Installing dependencies from requirements.txt... Please wait.")
            logger.info("Starting auto-install of dependencies.")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
                print("[+] Dependencies installed successfully!\n")
                logger.info("Dependencies installed successfully.")
                
                print("[*] Restarting ShadowKnight to load new modules...")
                os.execv(sys.executable, ['python'] + sys.argv)
            except subprocess.CalledProcessError as e:
                print(f"[-] Failed to install dependencies. Error: {e}")
                logger.error(f"Failed to install dependencies: {e}")
                sys.exit(1)
        else:
            print("[-] Cannot proceed without required dependencies. Exiting.")
            sys.exit(1)

# Run dependency check immediately
check_and_install_dependencies()

from colorama import init, Fore, Style
import dotenv

# Initialize colorama for Windows safe colors
init(autoreset=True)

# -----------------------------------------------------------------------------
# 3. INTERACTIVE .ENV CONFIGURATION
# -----------------------------------------------------------------------------
def setup_environment():
    env_file = Path(".env")
    
    if env_file.exists():
        dotenv.load_dotenv(env_file)
    
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key or api_key.startswith("[REDACTED"):
        print(Fore.YELLOW + "\n[!] Gemini API Key not found or was redacted.")
        print(Fore.CYAN + "[i] ShadowKnight requires a Google Gemini API Key for AI threat analysis.")
        print(Fore.CYAN + "[i] You can get one for free at: https://aistudio.google.com/app/apikey")
        
        new_key = input(Fore.YELLOW + "[?] Enter your Gemini API Key: " + Style.RESET_ALL).strip()
        
        if new_key:
            with open(env_file, "a") as f:
                f.write(f"\nGEMINI_API_KEY={new_key}\n")
            print(Fore.GREEN + "[+] API Key securely saved to .env file.")
            logger.info("API Key configured and saved to .env")
            dotenv.load_dotenv(env_file)
        else:
            print(Fore.RED + "[-] No API Key provided. AI features will fail.")
            logger.warning("No API key provided during setup.")

# -----------------------------------------------------------------------------
# 4. VISUALIZATION AND BRANDING
# -----------------------------------------------------------------------------
def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    
    banner = f"""
{Fore.CYAN}███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
{Fore.CYAN}██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
{Fore.CYAN}███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
{Fore.CYAN}╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
{Fore.CYAN}███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
{Fore.CYAN}╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ 
                                                   
{Fore.RED}██╗  ██╗███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗    
{Fore.RED}██║ ██╔╝████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝    
{Fore.RED}█████╔╝ ██╔██╗ ██║██║██║  ███╗███████║   ██║       
{Fore.RED}██╔═██╗ ██║╚██╗██║██║██║   ██║██╔══██║   ██║       
{Fore.RED}██║  ██╗██║ ╚████║██║╚██████╔╝██║  ██║   ██║       
{Fore.RED}╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝       
{Style.RESET_ALL}
    """
    print(banner)
    print(Fore.GREEN + " 🛡️  Enterprise Digital Forensics & Incident Response (DFIR) Framework")
    print(Fore.YELLOW + " 👨‍💻 Creator: Himanshu Yadav")
    print(Fore.WHITE + " 📜 Concept: Detects, analyzes, and preserves evidence of anti-forensics activity in real-time.")
    print("-" * 75 + "\n")

# -----------------------------------------------------------------------------
# 5. MENU ACTIONS
# -----------------------------------------------------------------------------
def run_realtime_engine():
    logger.info("Action: Launching Real-Time Engine")
    print(Fore.GREEN + "\n[*] Launching ShadowKnight Real-Time Engine...")
    print(Fore.YELLOW + "[!] Press Ctrl+C to stop the engine and return to the menu.\n" + Style.RESET_ALL)
    try:
        subprocess.run([sys.executable, "shadow_knight_realtime.py"])
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Engine stopped by user.")
        logger.info("Real-Time Engine stopped by user.")

def run_stress_test():
    logger.info("Action: Running Stress Test")
    print(Fore.GREEN + "\n[*] Launching End-to-End Stress Test...")
    print(Fore.YELLOW + "[i] This will simulate heavy load and test system limits." + Style.RESET_ALL)
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        subprocess.run([sys.executable, "shadow_knight_v4_stress_test.py"], env=env)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Stress Test stopped by user.")
        logger.info("Stress Test stopped by user.")

def run_unit_tests():
    logger.info("Action: Running Unit Tests")
    print(Fore.GREEN + "\n[*] Running Diagnostic Unit Tests via pytest..." + Style.RESET_ALL)
    try:
        subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"])
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Unit Tests stopped by user.")
        logger.info("Unit Tests stopped by user.")

def run_interactive_demo():
    logger.info("Action: Running Interactive Demo")
    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.CYAN + "   SHADOWKNIGHT INTERACTIVE DEMO (CAPABILITY SHOWCASE)")
    print(Fore.CYAN + "="*60 + Style.RESET_ALL)
    
    print(Fore.WHITE + "\n[STEP 1] BACKGROUND: A threat actor gains access and attempts to clear Windows Event Logs to hide their tracks.")
    time.sleep(3)
    
    print(Fore.RED + "\n[!] SIMULATED ATTACK: Executing `wevtutil cl Security` (Clearing Security Logs)...")
    time.sleep(2)
    
    print(Fore.YELLOW + "\n[*] BACKGROUND WORK (ShadowKnight Engine):")
    time.sleep(1.5)
    print(" ├── WMI/Polling layer detected suspicious process creation in < 50ms.")
    time.sleep(1.5)
    print(" ├── Emergency Snapshot Engine captured running process memory & network connections.")
    time.sleep(1.5)
    print(" ├── Pre-fetch analyzer backed up the execution context.")
    time.sleep(1.5)
    print(" └── Command line forwarded to Gemini AI for Threat Analysis...")
    time.sleep(3)
    
    print(Fore.GREEN + "\n[+] RESULT & OUTPUT:")
    print(Fore.WHITE + " ├── " + Fore.RED + "THREAT CLASSIFIED: CRITICAL (Defense Evasion)")
    print(Fore.WHITE + " ├── AI Explanation: 'wevtutil cl Security' is a known anti-forensics technique used to clear audit trails.")
    print(Fore.WHITE + " ├── MITRE ATT&CK: T1070.001 (Clear Windows Event Logs)")
    print(Fore.WHITE + " ├── Evidence captured and cryptographically timestamped via RFC 3161.")
    print(Fore.WHITE + " └── Saved to Evidence Vault for Court Admissibility.")
    
    print(Fore.CYAN + "\n[i] Demo complete. This represents the core pipeline of ShadowKnight.")
    logger.info("Interactive Demo completed successfully.")
    input(Fore.YELLOW + "\nPress ENTER to return to menu..." + Style.RESET_ALL)

def stop_all_processes():
    logger.info("Action: Stopping all processes")
    print(Fore.RED + "\n[*] Terminating all ShadowKnight background processes...")
    try:
        import psutil
        current_pid = os.getpid()
        killed_count = 0
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline') or []
                cmd_str = ' '.join(cmdline).lower()
                if 'python' in proc.info.get('name', '').lower() and proc.info.get('pid') != current_pid:
                    if 'shadow_knight' in cmd_str or 'pytest' in cmd_str:
                        print(f"[-] Killing Process ID {proc.info['pid']} ({cmd_str[:50]}...)")
                        proc.kill()
                        killed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        print(Fore.GREEN + f"[+] Successfully terminated {killed_count} rogue processes." + Style.RESET_ALL)
        logger.info(f"Terminated {killed_count} rogue processes.")
    except Exception as e:
        print(Fore.RED + f"[-] Error terminating processes: {e}" + Style.RESET_ALL)
        logger.error(f"Error terminating processes: {e}")
    
    input(Fore.YELLOW + "\nPress ENTER to return to menu..." + Style.RESET_ALL)

# -----------------------------------------------------------------------------
# 6. MAIN LOOP
# -----------------------------------------------------------------------------
def main_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "=== MASTER ACTION MENU ===")
        print(Fore.WHITE + "1. Launch ShadowKnight Engine (Real-Time Protection)")
        print(Fore.WHITE + "2. Run Interactive Demo (Showcase Capabilities)")
        print(Fore.WHITE + "3. Run End-to-End Stress Test")
        print(Fore.WHITE + "4. Run Diagnostic Unit Tests (pytest)")
        print(Fore.WHITE + "5. Stop All ShadowKnight Processes (Kill-Switch)")
        print(Fore.WHITE + "6. Exit")
        print(Fore.CYAN + "==========================")
        
        choice = input(Fore.YELLOW + "\n[?] Select an option (1-6): " + Style.RESET_ALL).strip()
        
        if choice == '1':
            run_realtime_engine()
        elif choice == '2':
            run_interactive_demo()
        elif choice == '3':
            run_stress_test()
        elif choice == '4':
            run_unit_tests()
        elif choice == '5':
            stop_all_processes()
        elif choice == '6':
            print(Fore.GREEN + "\n[*] Exiting ShadowKnight Controller. Stay secure!")
            logger.info("Application exited by user.")
            sys.exit(0)
        else:
            print(Fore.RED + "[-] Invalid selection. Please choose a number between 1 and 6." + Style.RESET_ALL)
            time.sleep(1)

if __name__ == "__main__":
    logger.info("ShadowKnight CLI Started.")
    setup_environment()
    main_menu()
