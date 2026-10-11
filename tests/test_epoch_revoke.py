"""Offline ASGI integration tests; no deployed gateway or production key required."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import test_security_hardening as security

if __name__ == "__main__":
    suite = unittest.TestSuite(security.SecurityHardeningTests(name) for name in ['test_changed_epoch_revokes_approval_and_execution', 'test_cross_turn_feedback_not_preserved', 'test_client_cannot_seed_session_with_signed_profile'])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
