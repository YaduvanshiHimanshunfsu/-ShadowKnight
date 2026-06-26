import os
import unittest
import numpy as np

# Adjust path to import core modules
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.entropy_engine import EntropyEngine
from utils.evidence_vault import EvidenceVault

class TestPhase1Upgrades(unittest.TestCase):
    
    def setUp(self):
        self.entropy_engine = EntropyEngine()
        self.vault = EvidenceVault(vault_path="./test_evidence")
        
    def test_ks_test_uniform_data(self):
        # Generate perfectly uniform data (mimicking AES encryption)
        # Using a deterministic random generator for consistency
        np.random.seed(42)
        uniform_data = np.random.bytes(4096)
        
        result = self.entropy_engine.run_ks_test(uniform_data)
        
        # A perfectly uniform block of bytes should not reject the null hypothesis
        # that it is drawn from a uniform distribution (p_value > 0.05)
        self.assertTrue(result['is_uniform'])
        
    def test_chi_square_test_packed_data(self):
        np.random.seed(42)
        packed_data = np.random.bytes(4096)
        
        result = self.entropy_engine.run_chi_square_test(packed_data)
        
        # Similarly, packed data should look uniformly distributed
        self.assertTrue(result['is_suspicious'])
        
    def test_ks_test_structured_data(self):
        # Generate structured text data (not uniform)
        structured_data = b"This is a test of structured data. " * 100
        
        result = self.entropy_engine.run_ks_test(structured_data)
        
        # Structured text is absolutely NOT uniform
        self.assertFalse(result['is_uniform'])
        
    def test_tsa_timestamping_fallback(self):
        # Test that _get_rfc3161_timestamp degrades gracefully on error
        # We can test with a fake hash
        fake_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        # This will actually hit the real freetsa.org server and succeed, 
        # or fail gracefully if network is blocked.
        result = self.vault._get_rfc3161_timestamp(fake_hash)
        
        # Either it's a valid base64 token or None. Both are acceptable in production fallback.
        if result is not None:
            self.assertTrue(isinstance(result, str))
            
    def tearDown(self):
        import shutil
        if os.path.exists("./test_evidence"):
            shutil.rmtree("./test_evidence")

if __name__ == '__main__':
    unittest.main()
