import contextlib
import io
import json
import unittest
from unittest.mock import Mock, patch

import main


def make_token(header=None, payload=None, signature=b"signature"):
    header = header or {"alg": "HS256", "typ": "JWT"}
    payload = payload or {"sub": "user-1", "role": "user"}
    return ".".join(
        (
            main.b64url_encode(json.dumps(header).encode()),
            main.b64url_encode(json.dumps(payload).encode()),
            main.b64url_encode(signature),
        )
    )


class TokenParsingTests(unittest.TestCase):
    def test_decodes_jwt_object_segments(self):
        header, payload, _ = main.decode_token(make_token())
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(payload["role"], "user")

    def test_rejects_malformed_and_non_object_segments(self):
        for token in (
            "one.two",
            "!.e30.c2ln",
            f"{main.b64url_encode(b'[]')}.{main.b64url_encode(b'{}')}.",
            f"{main.b64url_encode(b'{}')}.{main.b64url_encode(b'[]')}.",
        ):
            with self.subTest(token=token), self.assertRaises(main.TokenFormatError):
                main.decode_token(token)

    def test_rejects_noncanonical_base64url(self):
        with self.assertRaises(main.TokenFormatError):
            main.b64url_decode("Zh")

    def test_rejects_duplicate_json_members(self):
        header = main.b64url_encode(b'{"alg":"HS256","alg":"none"}')
        payload = main.b64url_encode(b'{"sub":"user"}')
        with self.assertRaises(main.TokenFormatError):
            main.decode_token(f"{header}.{payload}.")

    def test_info_does_not_print_claim_values(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main.print_token_info(make_token(payload={"sub": "private-user"}))
        self.assertIn("sub", output.getvalue())
        self.assertNotIn("private-user", output.getvalue())


class CandidateTests(unittest.TestCase):
    def test_claim_tampering_does_not_mutate_decoded_source(self):
        token = make_token()
        forged = main.attack_claim_tamper(token, {"role": "admin"}, None, "Authorization")
        _, original_payload, _ = main.decode_token(token)
        _, modified_payload, _ = main.decode_token(forged)
        self.assertEqual(original_payload["role"], "user")
        self.assertEqual(modified_payload["role"], "admin")

    def test_brute_force_only_checks_hs256_and_withholds_secret(self):
        header = main.b64url_encode(json.dumps({"alg": "HS256"}).encode())
        payload = main.b64url_encode(json.dumps({"sub": "user"}).encode())
        token = f"{header}.{payload}.{main.sign_hs256(header, payload, 'secret')}"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            found = main.attack_brute_force(token, None, None, "Authorization")
        self.assertEqual(found, "secret")
        self.assertNotIn("'secret'", output.getvalue())

        rs_token = make_token(header={"alg": "RS256"})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(
                main.attack_brute_force(rs_token, None, None, "Authorization")
            )


class ActiveProbeTests(unittest.TestCase):
    def test_active_probe_requires_authorization_acknowledgement(self):
        with patch.object(main.requests, "get") as get:
            with self.assertRaises(SystemExit) as error:
                main.main(["--token", make_token(), "--url", "https://example.test"])
        self.assertEqual(error.exception.code, 2)
        get.assert_not_called()

    def test_active_probe_verifies_tls_and_reports_inconclusive_status(self):
        response = Mock(status_code=200)
        output = io.StringIO()
        with patch.object(main.requests, "get", return_value=response) as get:
            with contextlib.redirect_stdout(output):
                result = main.main(
                    [
                        "--token",
                        make_token(),
                        "--attack",
                        "none",
                        "--url",
                        "https://example.test/audit",
                        "--authorized",
                    ]
                )
        self.assertEqual(result, 0)
        self.assertTrue(get.called)
        self.assertIs(get.call_args.kwargs["verify"], True)
        self.assertIs(get.call_args.kwargs["allow_redirects"], False)
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"][:7], "Bearer ")
        self.assertIn("inconclusive", output.getvalue())
        self.assertNotIn(make_token(), output.getvalue())

    def test_rejects_invalid_urls_and_header_names(self):
        for url, header in (
            ("file:///etc/passwd", "Authorization"),
            ("https://user:pass@example.test/", "Authorization"),
            ("https://example.test/", "Bad Header"),
        ):
            with self.subTest(url=url, header=header):
                with self.assertRaises(ValueError):
                    main.validate_target(url, header)


if __name__ == "__main__":
    unittest.main()
