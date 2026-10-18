import unittest
from unittest.mock import Mock

import requests

from sqlihawk import detect_db_error, parse_args, replace_query, response_signature, run_scan


class DetectorTests(unittest.TestCase):
    def test_detects_common_database_error(self):
        found = detect_db_error("Database says: You have an error in your SQL syntax")
        self.assertIsNotNone(found)
        self.assertEqual(found[0], "MySQL")

    def test_no_error_in_normal_body(self):
        self.assertIsNone(detect_db_error("<html><body>Welcome</body></html>"))

    def test_replace_query_preserves_path_and_fragment(self):
        result = replace_query("https://example.test/item?id=1#section", [("id", "2")])
        self.assertEqual(result, "https://example.test/item?id=2#section")

    def test_rejects_url_without_query_parameters(self):
        with self.assertRaises(ValueError):
            run_scan("https://example.test/")

    def test_requires_permission_acknowledgement(self):
        with self.assertRaises(SystemExit):
            parse_args(["--url", "https://example.test/?id=1"])

    def test_run_scan_with_mocked_session(self):
        session = Mock()
        baseline = Mock(spec=requests.Response)
        baseline.status_code = 200
        baseline.text = "<html>Product page</html>"
        baseline.headers = {}
        mutated = Mock(spec=requests.Response)
        mutated.status_code = 200
        mutated.text = "<html>Product page</html>"
        session.get.return_value = baseline
        report = run_scan("https://example.test/?id=1", delay=0, session=session)
        self.assertEqual(report["tool"], "SQLiHawk")
        self.assertEqual(report["results"][0]["parameter"], "id")
        self.assertIn(report["results"][0]["status"], {"possible", "no_signal"})
        self.assertGreaterEqual(session.get.call_count, 1)


if __name__ == "__main__":
    unittest.main()
