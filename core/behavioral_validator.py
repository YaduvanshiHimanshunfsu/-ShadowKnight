"""
SHADOWNET v4.0 - BEHAVIORAL AI (KEYLOGGER) VALIDATION
Specifically tests the AI's ability to differentiate between 
Natural Human Rhythm and Mechanical Bot/Keylogger Injection.
"""

import os
import random
import time
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment
load_dotenv()
api_key = os.getenv('GEMINI_API_KEY')

def test_behavior():
    print("="*70)
    print("🛡️  SHADOWNET v4.0 - BEHAVIORAL AI STRESS TEST")
    print("="*70)

    if not api_key:
        print("❌ Error: GEMINI_API_KEY not found.")
        return

    from .gemini_behavior_analyzer import GeminiBehaviorAnalyzer
    analyzer = GeminiBehaviorAnalyzer(api_key)

    # 1. Simulate HUMAN TYPING (High variance, natural jitter)
    human_timings = [random.randint(80, 280) for _ in range(25)]
    
    # 2. Simulate BOT/KEYLOGGER (Mechanical, zero variance, fixed 10ms delay)
    bot_timings = [10 for _ in range(25)]

    scenarios = [
        {"name": "Scenario A: Natural Human Input", "data": human_timings},
        {"name": "Scenario B: Mechanical Bot Injection (Keylogger)", "data": bot_timings}
    ]

    for sc in scenarios:
        print(f"\n[TESTING] {sc['name']}")
        print(f"Data Sample: {sc['data'][:10]}...")
        
        try:
            print("AI is analyzing entropy and variance...")
            result = analyzer.analyze_keystroke_pattern(sc['data'])
            
            if 'error' in result:
                print(f"⚠️  AI Analysis Delay/Quota: {result['error']}")
                continue

            input_type = result.get('input_type', 'unknown').upper()
            confidence = result.get('confidence', 0)
            is_human = result.get('is_human', False)
            
            print(f"VERDICT: {'✅ HUMAN' if is_human else '🚨 MALICIOUS BOT/KEYLOG'}")
            print(f"AI CLASSIFICATION: {input_type}")
            print(f"CONFIDENCE SCORE: {confidence:.2%}")
            print(f"AI REASONING: {result.get('assessment', 'N/A')}")
            
        except Exception as e:
            print(f"❌ Test Failed: {e}")
        
        print("-" * 50)

    print("\n" + "="*70)
    print("🏁 BEHAVIORAL VALIDATION COMPLETE")
    print("="*70)

if __name__ == "__main__":
    test_behavior()
