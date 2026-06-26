"""
SHADOWNET v4.0 - COMPREHENSIVE REAL-TIME STRESS TEST
This script simulates multiple attack vectors to verify the system's
Real-Time Detection (WMI), AI Analysis, and Forensic Preservation layers.

INSTRUCTIONS:
1. Ensure 'python shadow_knight_realtime.py' is running in another Administrator terminal.
2. Run this script: 'python shadow_knight_v4_stress_test.py'
"""

import subprocess
import time
import os
import sys

def print_banner():
    print("="*70)
    print("🛡️  SHADOWNET v4.0 - FULL SYSTEM CAPABILITY TEST")
    print("="*70)
    print("This will trigger multiple suspicious activities to verify detection.")
    print("Watch your ShadowKnight terminal for real-time alerts!")
    print("="*70 + "\n")

def run_test(name, command, description):
    print(f"👉 TESTING: {name}")
    print(f"   Description: {description}")
    print(f"   Command: {command}")
    
    try:
        # We use subprocess.Popen to ensure it's a real process creation event for WMI
        # and shell=True to allow command strings to execute.
        # We don't care if the command fails (access denied), detection happens at spawn.
        subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("   ✅ [SENT] Waiting for system response...")
    except Exception as e:
        print(f"   ❌ [FAILED TO DISPATCH]: {e}")
    
    time.sleep(3) # Space out tests to see individual alerts
    print("-" * 50)

def main():
    import platform
    import datetime
    os_type = platform.system().lower()
    
    print_banner()
    print(f"📍 Detected Platform: {os_type.upper()}")

    # CATEGORY 1: ANTI-FORENSICS
    if os_type == "windows":
        run_test("Log Clearing (wevtutil)", "wevtutil cl Application", "Attempting to wipe System logs.")
        run_test("Secure File Deletion (sdelete)", "sdelete.exe -p 3 sensitive.txt", "Forensic wipe.")
    else:
        run_test("Log Clearing (rm)", "rm -rf /var/log/syslog.1", "Attempting to delete log rotations.")
        run_test("Secure File Deletion (shred)", "shred -u sensitive.txt", "Using GNU shred for secure wipe.")

    # CATEGORY 2: RANSOMWARE PREPARATION / SYSTEM TAMPERING
    if os_type == "windows":
        run_test("Shadow Copy Deletion", "vssadmin delete shadows /all /quiet", "Preventing recovery.")
        run_test("Registry Persistence", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Alert /t REG_SZ /d \"calc.exe\"", "Persistence.")
    else:
        run_test("History Clearing", "history -c", "Wiping bash/zsh history.")
        run_test("Cron Persistence", "echo '* * * * * root /tmp/evil' >> /etc/crontab", "Adding malicious cron job.")

    # CATEGORY 3: CREDENTIAL ACCESS
    if os_type == "windows":
        run_test("Credential Dumping", "mimikatz.exe \"privilege::debug\"", "Mimikatz simulation.")
    else:
        run_test("Shadow File Access", "cat /etc/shadow", "Attempting to read password hashes.")

    # CATEGORY 4: OBFUSCATION & STEALTH
    if os_type == "windows":
        run_test("Encoded PowerShell", "powershell -EncodedCommand JABhID0gMSArIDE=", "Base64 payload.")
    else:
        run_test("Python Obfuscation", "python3 -c \"import base64; exec(base64.b64decode('cHJpbnQoJ0hlbGxvJyk='))\"", "Encoded python execution.")

    # CATEGORY 6: KEYLOGGER & BEHAVIORAL DETECTION
    print("👉 TESTING: Keylogger Detection (Mechanical Pattern)")
    print("   Description: Simulating bot-driven keystroke injection vs Human typing.")
    
    try:
        import statistics
        from core.gemini_behavior_analyzer import GeminiBehaviorAnalyzer
        from dotenv import load_dotenv
        load_dotenv()
        
        # Scenario A: Mechanical Bot (Low Jitter)
        bot_data = [10, 10, 10, 11, 10, 10, 10, 9, 10, 10]
        # Scenario B: Human (High Jitter)
        human_data = [120, 250, 80, 400, 150, 90, 220, 110]
        
        # 1. Local Statistical Check (Offline Defense)
        print("   [STEP 1] Running Local Jitter Analysis (Offline)...")
        bot_std = statistics.stdev(bot_data)
        if bot_std < 10:
            print(f"   ✅ [LOCAL VERDICT] 🚨 KEYLOGGER DETECTED (StdDev: {bot_std:.2f}ms)")
        else:
            print(f"   ❌ [LOCAL VERDICT] Failed to detect (StdDev: {bot_std:.2f}ms)")
            
        # 2. AI Behavioral Check (Deep Intelligence)
        print("   [STEP 2] Running AI Behavioral Analysis (Gemini)...")
        analyzer = GeminiBehaviorAnalyzer(os.getenv('GEMINI_API_KEY'))
        res = analyzer.analyze_keystroke_pattern(bot_data)
        
        if 'error' in res:
             print(f"   ⚠️  AI Analysis delayed (Quota/Network): {res['error']}")
        else:
            is_bot = not res.get('is_human')
            verdict = "🚨 BOT/KEYLOGGER" if is_bot else "Human"
            print(f"   ✅ [AI VERDICT] {verdict} (Confidence: {res.get('confidence', 0):.2%})")
            print(f"   Reasoning: {res.get('assessment', 'N/A')[:60]}...")
            
            if is_bot:
                print("\n   [STEP 3] Generating Forensic Report & Snapshot...")
                from core.emergency_snapshot import EmergencySnapshotEngine
                from core.incident_report_generator import IncidentReportGenerator
                
                # 1. Take Emergency Snapshot
                snapshot_engine = EmergencySnapshotEngine("./evidence")
                snapshot_id = snapshot_engine.emergency_snapshot(
                    threat_type="behavioral_keylogger",
                    command="BEHAVIORAL_DETECTED",
                    process_info={'name': 'python.exe', 'pid': os.getpid(), 'args': 'simulated_keylogger'}
                )
                
                # 2. Generate Incident Report
                reporter = IncidentReportGenerator("./evidence")
                report_path = reporter.generate_incident_report({
                    'incident_id': f"INC-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-KEYLOG",
                    'threat_type': 'behavioral_keylogger',
                    'command': 'Keystroke Pattern Anomaly',
                    'process_info': {'name': 'python.exe', 'pid': os.getpid(), 'user': os.getlogin()},
                    'snapshot_id': snapshot_id,
                    'detection_time': datetime.datetime.now().isoformat(),
                    'ai_analysis': res,
                    'severity': 'HIGH'
                })
                print(f"   📄 Report Generated: {report_path}")

    except Exception as e:
        print(f"   ⚠️  Behavioral Test Error: {e}")

    print("\n" + "="*70)
    print("🏁 COMPREHENSIVE TEST COMPLETE")
    print("Check the 'evidence/incidents' folder for generated forensic reports.")
    print("="*70)

if __name__ == "__main__":
    main()
