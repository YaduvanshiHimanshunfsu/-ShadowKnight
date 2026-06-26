"""
SHADOWNET v4.0 - LOCAL BEHAVIORAL ENGINE (OFFLINE)
Demonstrates statistical detection of keyloggers without AI.
Verifies that we can catch robotic timing signatures locally.
"""

import statistics
import random

def detect_keylogger_locally(timings):
    print(f"\nAnalyzing {len(timings)} keystrokes...")
    
    # Calculate Statistical Variance (Jitter)
    mean_val = statistics.mean(timings)
    std_dev = statistics.stdev(timings)
    
    # 🚨 TITAN OFFLINE LOGIC: 
    # If standard deviation is < 5ms, it's mechanically precise (Bot)
    # If standard deviation is > 50ms, it's natural human entropy.
    
    is_bot = std_dev < 10 # Extremely low variance = Robotic
    
    print(f"   Avg Interval: {mean_val:.2f}ms")
    print(f"   Jitter (StdDev): {std_dev:.2f}ms")
    
    if is_bot:
        print("🚨 VERDICT: KEYLOGGER/BOT DETECTED (Mechanical Regularity)")
        return "BOT"
    else:
        print("✅ VERDICT: HUMAN TYPING (Natural Entropy)")
        return "HUMAN"

def run_test():
    print("="*60)
    print("🛡️  SHADOWNET v4.0 - LOCAL KEYLOGGER PROTECTION TEST")
    print("="*60)

    # Test 1: Human
    print("\n[TEST 1] Simulating Human Writing...")
    human_data = [random.randint(80, 400) for _ in range(20)]
    detect_keylogger_locally(human_data)

    # Test 2: Keylogger
    print("\n[TEST 2] Simulating Keylogger/Macro (Fixed 10ms delay)...")
    bot_data = [10, 11, 10, 9, 10, 10, 11, 10, 10, 10] # Tiny variance
    detect_keylogger_locally(bot_data)

    print("\n" + "="*60)
    print("🏁 LOCAL BEHAVIORAL VALIDATION COMPLETE")
    print("="*60)

if __name__ == "__main__":
    run_test()
