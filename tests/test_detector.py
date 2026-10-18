import unittest
from unittest.mock import Mock

import requests

from sqlihawk import detect_db_error, materially_different, parse_args, replace_query, run_scan


def fake_response(status=200, body="<html>" + ("Product page " * 20) + "</html>"):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.text = body
    return response


class DetectorTests(unittest.TestCase):
    def test_detects_common_database_error(self):
        found = detect_db_error("Database says: You have an error in your SQL syntax")
        self.assertIsNotNone(found)
        self.assertEqual(found[0], "MySQL")

    def test_no_error_in_normal_body(self):
        self.assertIsNone(detect_db_error("<html><body>Welcome</body></html>"))

    def test_replace_query_preserves_path_and_drops_fragment(self):
        result = replace_query("https://example.test/item?id=1#section", [("id", "2")])
        self.assertEqual(result, "https://example.test/item?id=2")

    def test_detects_material_response_difference(self):
        left = fake_response(body="<html>" + ("A" * 500) + "</html>")
        right = fake_response(body="<html>" + ("B" * 500) + "</html>")
        self.assertTrue(materially_different(left, right))

    def test_ignores_same_response(self):
        self.assertFalse(materially_different(fake_response(), fake_response()))

    def test_rejects_url_without_query_parameters(self):
        with self.assertRaises(ValueError):
            run_scan("https://example.test/")

    def test_rejects_credentials_in_url(self):
        with self.assertRaises(ValueError):
            run_scan("https://user:pass@example.test/?id=1")

    def test_requires_permission_acknowledgement(self):
        with self.assertRaises(SystemExit):
            parse_args(["--url", "https://example.test/?id=1"])

    def test_run_scan_with_mocked_session(self):
        session = Mock()
        session.get.return_value = fake_response()
        report = run_scan("https://example.test/?id=1", delay=0, session=session)
        self.assertEqual(report["tool"], "SQLiHawk")
        self.assertEqual(report["results"][0]["parameter"], "id")
        self.assertIn(report["results"][0]["status"], {"possible", "no_signal", "error"})
        self.assertGreaterEqual(session.get.call_count, 1)
        self.assertFalse(report["redirects_followed"])


if __name__ == "__main__":
    unittest.main()
