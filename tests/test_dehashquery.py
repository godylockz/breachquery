import argparse
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import dehashquery


class DomainTests(unittest.TestCase):
    def test_normalize_domain_accepts_urls_and_idna(self) -> None:
        self.assertEqual(
            dehashquery.normalize_domain(" https://www.Exämple.com/path?q=1 "),
            "xn--exmple-cua.com",
        )

    def test_normalize_domain_rejects_unsafe_values(self) -> None:
        for value in ("../outside", "https://user@example.com", "file://example.com", "bad host"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                dehashquery.normalize_domain(value)

    def test_load_domains_deduplicates_canonical_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_file = Path(directory) / "domains.txt"
            domain_file.write_text(
                "Example.COM\nhttps://www.example.com/path\nsecond.example\n",
                encoding="utf-8",
            )
            args = argparse.Namespace(domains=str(domain_file), domain=None)
            self.assertEqual(dehashquery.load_domains(args), ["example.com", "second.example"])

    def test_load_domains_rejects_path_traversal(self) -> None:
        args = argparse.Namespace(domains=None, domain="../../outside")
        with self.assertRaises(SystemExit):
            dehashquery.load_domains(args)


class SecretHandlingTests(unittest.TestCase):
    def test_resolve_api_key_uses_environment(self) -> None:
        with patch.dict(os.environ, {"DEHASHED_API_KEY": " env-key "}, clear=True):
            self.assertEqual(dehashquery.resolve_api_key(), "env-key")

    def test_parser_rejects_api_key_argument(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            dehashquery.build_parser().parse_args(["credits", "--api-key", "secret"])

    @patch("dehashquery.getpass.getpass", return_value="Password123")
    @patch("dehashquery.resolve_api_key", return_value="api-key")
    @patch("dehashquery.DehashedClient")
    def test_password_check_hashes_hidden_input(
        self, client_type: Mock, _resolve: Mock, _prompt: Mock
    ) -> None:
        client_type.return_value.search_password.return_value = {"results_found": 0}
        args = argparse.Namespace(rate=1)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(dehashquery.cmd_password_check(args), 0)
        expected = hashlib.sha256(b"Password123").hexdigest()
        client_type.return_value.search_password.assert_called_once_with(expected)


class CacheTests(unittest.TestCase):
    def test_load_cached_data_accepts_legacy_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "allData.json"
            cache.write_text(json.dumps({"entries": [{"email": "user@example.com"}]}),
                             encoding="utf-8")
            self.assertEqual(
                dehashquery.load_cached_data(cache),
                {"entries": [{"email": "user@example.com"}]},
            )

    def test_load_cached_data_rejects_foreign_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "allData.json"
            cache.write_text(
                json.dumps({"source": "hacknotice-research8-v1", "entries": []}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "not a DeHashed"):
                dehashquery.load_cached_data(cache)


if __name__ == "__main__":
    unittest.main()
