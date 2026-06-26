"""
ShadowKnight Real-Time Detection Test
This script will run ShadowKnight and test it with forensic commands
"""
import subprocess
import time
import sys

print("="*80)
print("🛡️  SHADOWNET REAL-TIME DETECTION TEST")
print("="*80)
print("\n[1] Starting ShadowKnight in background...")

# Start ShadowKnight
shadow_knight = subprocess.Popen(
    ['python', 'shadow_knight_realtime.py'],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

print("[2] Waiting 10 seconds for initialization...")
time.sleep(10)

print("\n[3] Testing forensic commands...")
print("    - Running: wevtutil qe Application /c:1")
subprocess.run(['wevtutil', 'qe', 'Application', '/c:1', '/f:text'], 
               capture_output=True, timeout=5)

time.sleep(2)

print("    - Running: cipher (will terminate quickly)")
cipher_proc = subprocess.Popen(['cipher', '/w:C:\\temp'], 
                                stdout=subprocess.DEVNULL, 
                                stderr=subprocess.DEVNULL)
time.sleep(1)
cipher_proc.terminate()

print("\n[4] Waiting 5 seconds for detections...")
time.sleep(5)

print("\n[5] Stopping ShadowKnight...")
shadow_knight.terminate()
shadow_knight.wait(timeout=5)

print("\n✅ Test complete! Check the ShadowKnight output above for detections.")
print("="*80)
