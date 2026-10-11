"""Offline ASGI integration tests; no deployed gateway or production key required."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import test_security_hardening as security

if __name__ == "__main__":
    suite = unittest.TestSuite(security.SecurityHardeningTests(name) for name in ['test_http_allow_and_single_use_consume', 'test_runtime_cannot_register_approve_or_anchor', 'test_online_behavior_alignment_blocks_recipient', 'test_approval_is_exact_and_single_action'])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
