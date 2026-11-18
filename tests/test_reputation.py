import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.reputation import check_reputation # type: ignore


class ReputationTests(unittest.TestCase):

    @patch("src.reputation.requests.get")
    def test_missing_api_key(self, mock_get):
        with patch.dict("os.environ", {}, clear=True):
            result = check_reputation(
                "https://example.com/test", "url"
            )
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("not configured", result["reason"])
        mock_get.assert_not_called()

    @patch("src.reputation.requests.get")
    def test_missing_report(self, mock_get):
        mock_get.return_value = Mock(status_code=404)
        mock_get.return_value.raise_for_status = Mock()

        with patch.dict("os.environ", {"VT_API_KEY": "test-key"}):
            result = check_reputation("https://example.com/test", "url")

        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("No existing", result["reason"])

    @patch("src.reputation.requests.get")
    def test_unauthorized_key(self, mock_get):
        mock_get.return_value = Mock(status_code=401)

        with patch.dict("os.environ", {"VT_API_KEY": "test-key"}):
            result = check_reputation("example.com", "domain")

        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("401", result["reason"])

    @patch("src.reputation.requests.get")
    def test_rate_limit(self, mock_get):
        mock_get.return_value = Mock(status_code=429)

        with patch.dict("os.environ", {"VT_API_KEY": "test-key"}):
            result = check_reputation("example.com", "domain")

        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("rate limit", result["reason"].lower())
    @patch("src.reputation.requests.get")
    def test_reserved_test_domain_skips_external_lookup(self, mock_get):
        with patch.dict("os.environ", {"VT_API_KEY": "test-key"}):
            result = check_reputation("login.example.test", "domain")

        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("Reserved .test domain", result["reason"])
        mock_get.assert_not_called()

if __name__ == "__main__":
    unittest.main(verbosity=2)
