"""Unit tests for blkchain.httputil.read_json_body.

Stdlib unittest only (no pytest dependency). These tests import ONLY
blkchain.httputil, never blkchain.embed_server, so no MLX model is loaded and
no server has to run. A fake handler stands in for BaseHTTPRequestHandler: its
`.headers` is a plain dict and its `.rfile` is an io.BytesIO.

Together they show the bug is closed: read_json_body RETURNS an error tuple for
a bogus Content-Length and for an oversized body, where the old inline
`int(self.headers.get("Content-Length", 0))` + unbounded `rfile.read(length)`
would raise (killing the handler thread) or over-allocate.
"""
import io
import json
import time
import unittest
from unittest import mock

from blkchain.httputil import _json_sanitize, host_allowed, json_content_type, read_json_body, send_json

MAX = 1024  # small cap so an "oversized" body is cheap to construct


class FakeHandler:
    """Minimal stand-in: dict headers + BytesIO body, like the real handler."""

    def __init__(self, body: bytes, content_length):
        self.rfile = io.BytesIO(body)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length


class ReadJsonBodyTest(unittest.TestCase):
    def test_valid_json(self):
        body = b'{"query": "hello", "top_k": 3}'
        h = FakeHandler(body, str(len(body)))
        obj, code, msg = read_json_body(h, MAX)
        self.assertEqual(obj, {"query": "hello", "top_k": 3})
        self.assertIsNone(code)
        self.assertIsNone(msg)

    def test_missing_content_length_is_empty_dict(self):
        h = FakeHandler(b"", None)
        obj, code, msg = read_json_body(h, MAX)
        self.assertEqual(obj, {})
        self.assertIsNone(code)
        self.assertIsNone(msg)

    def test_non_numeric_content_length(self):
        # Old code: int("abc") raised ValueError before the try -> dead thread.
        h = FakeHandler(b'{"query": "x"}', "abc")
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)
        self.assertEqual(msg, "invalid Content-Length")

    def test_negative_content_length(self):
        h = FakeHandler(b'{"query": "x"}', "-5")
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)
        self.assertEqual(msg, "invalid Content-Length")

    def test_oversized_body_413(self):
        # Claim a length past the cap; helper rejects BEFORE reading/allocating.
        h = FakeHandler(b"", str(MAX + 1))
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 413)
        self.assertEqual(msg, "request body too large")

    def test_very_long_numeric_content_length_is_rejected(self):
        h = FakeHandler(b"", "9" * 5000)
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 413)
        self.assertEqual(msg, "request body too large")

    def test_incomplete_body_is_rejected(self):
        h = FakeHandler(b"{}", "10")
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)
        self.assertEqual(msg, "incomplete request body")

    def test_read_timeout_is_rejected(self):
        class TimedOutReader:
            def read(self, _length):
                raise TimeoutError("read timed out")

        h = FakeHandler(b"", "10")
        h.rfile = TimedOutReader()
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 408)
        self.assertEqual(msg, "request body timed out")

    def test_drip_does_not_extend_body_deadline(self):
        class DripReader:
            def __init__(self):
                self.data = b'{"x":1}'

            def read1(self, _length):
                time.sleep(0.03)
                chunk, self.data = self.data[:1], self.data[1:]
                return chunk

            def read(self, length):
                chunks = []
                for _ in range(length):
                    chunks.append(self.read1(1))
                return b"".join(chunks)

        h = FakeHandler(b"", "7")
        h.rfile = DripReader()
        with mock.patch("blkchain.httputil.BODY_READ_SECONDS", 0.05):
            obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 408)
        self.assertEqual(msg, "request body timed out")

    def test_malformed_json_400(self):
        body = b"{not valid json"
        h = FakeHandler(body, str(len(body)))
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)
        self.assertTrue(msg.startswith("bad json:"))

    def test_oversized_body_not_over_read(self):
        # A body exactly at the cap is accepted and read in full.
        payload = b'{"k": "' + b"a" * (MAX - 10) + b'"}'
        self.assertLessEqual(len(payload), MAX)
        h = FakeHandler(payload, str(len(payload)))
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(code)
        self.assertEqual(obj["k"], "a" * (MAX - 10))


class NonDictBodyTest(unittest.TestCase):
    """P4: a JSON body that is not an object must be a 400, not crash the caller
    that immediately does req.get(...)."""

    def test_list_body_400(self):
        body = b"[1, 2, 3]"
        h = FakeHandler(body, str(len(body)))
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)

    def test_string_body_400(self):
        body = b'"just a string"'
        h = FakeHandler(body, str(len(body)))
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)

    def test_number_body_400(self):
        body = b"42"
        h = FakeHandler(body, str(len(body)))
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)


class StrictContentLengthTest(unittest.TestCase):
    """Content-Length must be strict ascii digits: Python's int() accepts
    underscores and unicode digits, which is a smuggling/parse-confusion risk."""

    def test_underscore_length_rejected(self):
        h = FakeHandler(b"{}", "1_000")
        obj, code, msg = read_json_body(h, MAX)
        self.assertEqual(code, 400)

    def test_unicode_digit_length_rejected(self):
        h = FakeHandler(b"{}", "１２")  # fullwidth 12
        obj, code, msg = read_json_body(h, MAX)
        self.assertEqual(code, 400)


class SendErrorLogInjectionTest(unittest.TestCase):
    """send_error must not let an attacker-controlled exception message forge
    extra log lines (newline/CR in the message)."""

    def test_newlines_in_message_are_neutralized(self):
        import sys
        from blkchain.httputil import send_error

        class Out:
            def __init__(self):
                self.wfile = io.BytesIO()

            def send_response(self, code):
                pass

            def send_header(self, *a):
                pass

            def end_headers(self):
                pass

        err = io.StringIO()
        real = sys.stderr
        sys.stderr = err
        try:
            send_error(Out(), 500, "internal error", exc=RuntimeError("a\n[error] FORGED: b"))
        finally:
            sys.stderr = real
        first_line = err.getvalue().splitlines()[0]
        self.assertIn("[error]", first_line)
        self.assertIn("FORGED", first_line)  # folded onto one line, not a new record


class StrictJsonTest(unittest.TestCase):
    """Responses must be strict JSON: NaN and Inf become null."""

    def test_sanitize_replaces_non_finite(self):
        obj = {"results": [{"score": float("nan"), "x": 1.0},
                           {"score": float("inf"), "y": [float("-inf"), 2]}]}
        clean = _json_sanitize(obj)
        json.dumps(clean, allow_nan=False)  # raises on any remaining NaN or Inf
        self.assertIsNone(clean["results"][0]["score"])
        self.assertIsNone(clean["results"][1]["score"])
        self.assertIsNone(clean["results"][1]["y"][0])
        self.assertEqual(clean["results"][0]["x"], 1.0)

    def test_send_json_writes_strict_json(self):
        class Out:
            def __init__(self):
                self.wfile = io.BytesIO()
                self.status = None

            def send_response(self, code):
                self.status = code

            def send_header(self, *a):
                pass

            def end_headers(self):
                pass

        h = Out()
        send_json(h, 200, {"scores": [float("nan"), 0.5, float("inf")]})

        def reject(token):
            raise ValueError(f"non-strict JSON constant {token}")

        body = json.loads(h.wfile.getvalue(), parse_constant=reject)
        self.assertEqual(h.status, 200)
        self.assertEqual(body, {"scores": [None, 0.5, None]})



class RequestOriginTest(unittest.TestCase):
    def test_json_content_type(self):
        for value, want in (("application/json", True), ("Application/JSON; charset=utf-8", True),
                            ("text/plain", False), ("application/x-www-form-urlencoded", False),
                            ("multipart/form-data; boundary=x", False), (None, False)):
            with self.subTest(value=value):
                headers = {} if value is None else {"Content-Type": value}
                self.assertEqual(json_content_type(headers), want)

    def test_host_allowed_on_a_loopback_bind(self):
        for value, want in (("127.0.0.1:8100", True), ("localhost:8100", True), ("LOCALHOST", True),
                            ("[::1]:8100", True), ("127.0.0.2", True),
                            ("evil.example:8100", False), ("localhost.evil.example", False),
                            ("evil@127.0.0.1", False), ("127.0.0.1/x", False), ("", False), (None, False),
                            ("192.168.1.10:8100", False)):
            with self.subTest(value=value):
                headers = {} if value is None else {"Host": value}
                self.assertEqual(host_allowed(headers, "127.0.0.1"), want)

    def test_host_allowed_on_other_binds(self):
        self.assertTrue(host_allowed({"Host": "10.0.0.5:8100"}, "10.0.0.5"))
        self.assertFalse(host_allowed({"Host": "evil.example"}, "10.0.0.5"))
        self.assertTrue(host_allowed({"Host": "evil.example"}, "0.0.0.0"))
        self.assertTrue(host_allowed({"Host": "evil.example"}, "::"))


if __name__ == "__main__":
    unittest.main()
