import os
import unittest
import platform
import time
from datetime import datetime, timedelta

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.ntfs_artifact_parser import NTFSArtifactParser
from core.behavior_chain import BehaviorChainTracker
from core.ads_detector import ADSDetector
from core.prefetch_analyzer import PrefetchAnalyzer

class TestPhase2Upgrades(unittest.TestCase):
    
    def setUp(self):
        self.mft_parser = NTFSArtifactParser()
        self.chain_tracker = BehaviorChainTracker(time_window_minutes=5)
        self.ads_detector = ADSDetector()
        self.prefetch_analyzer = PrefetchAnalyzer()
        
    def test_behavioral_chain_detection(self):
        user = "test_attacker"
        
        # Simulating Reconnaissance -> Defense Evasion Chain
        res1 = self.chain_tracker.analyze_chain(user, "whoami /priv")
        self.assertFalse(res1["chain_detected"])
        
        res2 = self.chain_tracker.analyze_chain(user, "vssadmin delete shadows /all")
        self.assertFalse(res2["chain_detected"])
        
        # The 3rd command completes the Ransomware_Preparation chain 
        # (vssadmin + wevtutil are both in the stage list)
        res3 = self.chain_tracker.analyze_chain(user, "wevtutil cl Security")
        self.assertTrue(res3["chain_detected"])
        self.assertEqual(res3["chain_name"], "Ransomware_Preparation")
        self.assertEqual(res3["multiplier"], 2.0)
        
    def test_behavioral_chain_window_expiry(self):
        user = "slow_attacker"
        
        # Override internal clock for testing
        past_time = datetime.now() - timedelta(minutes=10)
        
        # Insert old event
        self.chain_tracker.user_history[user] = __import__('collections').deque()
        self.chain_tracker.user_history[user].append((past_time, "vssadmin delete shadows"))
        
        # Insert current event
        res = self.chain_tracker.analyze_chain(user, "wevtutil cl Security")
        
        # Should be False because the first event was outside the 5-minute window
        self.assertFalse(res["chain_detected"])

    def test_mft_parser_fallback(self):
        # We test that the parser gracefully falls back on a dummy file
        dummy_file = "dummy_test_file.txt"
        with open(dummy_file, "w") as f:
            f.write("test")
            
        result = self.mft_parser.extract_mft_timestamps(dummy_file)
        
        self.assertIsNotNone(result["si_creation"])
        self.assertIsNotNone(result["fn_creation"])
        
        os.remove(dummy_file)

    def test_ads_detector(self):
        # We just test that the detector returns a valid dictionary structure
        result = self.ads_detector.scan_file("C:\\Windows\\System32\\cmd.exe")
        self.assertIn("has_ads", result)
        self.assertIn("streams", result)
        self.assertIn("error", result)

if __name__ == '__main__':
    unittest.main()
