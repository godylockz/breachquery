import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path
from unittest.mock import Mock, patch

import hacknoticequery


class CredentialTests(unittest.TestCase):
    @patch("hacknoticequery.Path.is_file", return_value=False)
    def test_integration_key_takes_precedence(self, _is_file: Mock) -> None:
        values = {
            "HACKNOTICE_INTEGRATION_KEY": " integration-key ",
            "HACKNOTICE_API_KEY": "api-key",
            "HACKNOTICE_EMAIL": "user@example.com",
            "HACKNOTICE_PASSWORD": "password",
        }
        with patch.dict(os.environ, values, clear=True):
            self.assertEqual(
                hacknoticequery.resolve_credentials(),
                {"integration_key": "integration-key"},
            )

    def test_parser_rejects_secret_arguments(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            hacknoticequery.build_parser().parse_args(
                ["verify", "--integration-key", "secret"]
            )


class ClientTests(unittest.TestCase):
    @patch("hacknoticequery.time.sleep")
    @patch("hacknoticequery.requests.Session")
    def test_integration_key_header_and_verify_endpoint(
        self, session_type: Mock, _sleep: Mock
    ) -> None:
        session = session_type.return_value
        session.headers = {}
        response = Mock(status_code=200)
        response.json.return_value = {"valid": True}
        session.request.return_value = response

        client = hacknoticequery.HackNoticeClient(
            {"integration_key": "secret"}, min_interval=1.0
        )
        self.assertEqual(session.headers["X-HackNotice-Integration-Key"], "secret")
        self.assertEqual(client.verify(), {"valid": True})
        session.request.assert_called_once_with(
            "POST",
            f"{hacknoticequery.API_BASE_URL}{hacknoticequery.VERIFY_PATH}",
            timeout=hacknoticequery.REQUEST_TIMEOUT,
        )

    @patch("hacknoticequery.time.sleep")
    @patch("hacknoticequery.requests.Session")
    def test_jwt_sign_in_uses_expected_headers(self, session_type: Mock, _sleep: Mock) -> None:
        session = session_type.return_value
        session.headers = {}
        response = Mock(status_code=200)
        response.json.return_value = {"token": "jwt-token"}
        session.request.return_value = response

        hacknoticequery.HackNoticeClient(
            {
                "api_key": "api-key",
                "email": "user@example.com",
                "account_secret": "password",
            },
            min_interval=1.0,
        )

        self.assertEqual(session.headers["Authorization"], "JWT jwt-token")
        self.assertEqual(session.headers["apikey"], "api-key")
        session.request.assert_called_once_with(
            "POST",
            f"{hacknoticequery.API_BASE_URL}{hacknoticequery.SIGN_IN_PATH}",
            timeout=hacknoticequery.REQUEST_TIMEOUT,
            data={"email": "user@example.com", "password": "password"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )


class QueryTests(unittest.TestCase):
    def test_map_record_moves_non_plaintext_password_to_hash(self) -> None:
        entry = hacknoticequery.map_record(
            {
                "email": "user@example.com",
                "password": "5f4dcc3b5aa765d61d8327deb882cf99",
                "passwordType": "md5",
                "hackname": "Example breach",
            }
        )
        self.assertEqual(entry["password"], "")
        self.assertEqual(entry["hashed_password"], "5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertEqual(entry["database_name"], "Example breach")

    def test_build_body_has_bounded_domain_query(self) -> None:
        args = argparse.Namespace(days=30, searchtype="wildcard_pre")
        with patch("hacknoticequery.date") as date_type:
            date_type.today.return_value = date(2026, 9, 23)
            body = hacknoticequery.build_body("example.com", args)
        self.assertEqual(body["term"], "example.com")
        self.assertEqual(body["startdate"], "2026-08-24")
        self.assertEqual(body["enddate"], "2026-09-23")
        self.assertTrue(body["domainfilter"])
        self.assertTrue(body["credsonly"])

    def test_fetch_entries_stops_after_short_page(self) -> None:
        client = Mock()
        client.search_term.return_value = [{"email": "user@example.com"}]
        entries = hacknoticequery.fetch_entries(client, {}, pages=10)
        self.assertEqual(entries[0]["email"], "user@example.com")
        client.search_term.assert_called_once_with({}, 0)

    def test_default_output_is_provider_specific(self) -> None:
        args = hacknoticequery.build_parser().parse_args(["dump", "-d", "example.com"])
        self.assertEqual(args.output_dir, "output/hacknotice")

    def test_parser_rejects_non_positive_limits(self) -> None:
        parser = hacknoticequery.build_parser()
        for argv in (
            ["dump", "-d", "example.com", "--days", "0"],
            ["dump", "-d", "example.com", "--max-pages", "-1"],
            ["verify", "--min-interval", "0.5"],
        ):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser.parse_args(argv)


class CacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.args = argparse.Namespace(days=90, searchtype="wildcard_pre")

    def test_load_cached_entries_accepts_matching_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "allData.json"
            cache.write_text(
                json.dumps(
                    {
                        "source": hacknoticequery.CACHE_SOURCE,
                        "domain": "example.com",
                        "window_days": 90,
                        "searchtype": "wildcard_pre",
                        "entries": [{"email": "user@example.com"}],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                hacknoticequery.load_cached_entries(cache, "example.com", self.args),
                [{"email": "user@example.com"}],
            )

    def test_load_cached_entries_rejects_foreign_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "allData.json"
            cache.write_text(json.dumps({"entries": []}), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "not a HackNotice"):
                hacknoticequery.load_cached_entries(cache, "example.com", self.args)

    @patch("hacknoticequery.resolve_credentials", side_effect=AssertionError("unexpected auth"))
    @patch("hacknoticequery.DumpProcessor")
    def test_cached_dump_does_not_require_credentials(
        self, processor_type: Mock, _resolve: Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory) / "example.com"
            cache_dir.mkdir()
            (cache_dir / "allData.json").write_text(
                json.dumps(
                    {
                        "source": hacknoticequery.CACHE_SOURCE,
                        "domain": "example.com",
                        "window_days": 90,
                        "searchtype": "wildcard_pre",
                        "entries": [{"email": "user@example.com"}],
                    }
                ),
                encoding="utf-8",
            )
            args = hacknoticequery.build_parser().parse_args(
                ["dump", "-d", "example.com", "--output-dir", directory]
            )
            with redirect_stdout(io.StringIO()):
                self.assertEqual(hacknoticequery.cmd_dump(args), 0)
            processor_type.return_value.process.assert_called_once_with(
                [{"email": "user@example.com"}]
            )


if __name__ == "__main__":
    unittest.main()
