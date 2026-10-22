import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from hdrscope.audit import evaluate_headers, grade_from_score
from hdrscope.cli import run, json_report, text_report
from hdrscope.fetch import FetchError, normalize_url, audit_url

GOOD_HEADERS = {
    "Strict-Transport-Security": ["max-age=31536000; includeSubDomains; preload"],
    "Content-Security-Policy": ["default-src 'self'; script-src 'self'; frame-ancestors 'none'"],
    "X-Content-Type-Options": ["nosniff"],
    "Referrer-Policy": ["strict-origin-when-cross-origin"],
    "Permissions-Policy": ["camera=(), microphone=(), geolocation=()"],
    "Cross-Origin-Opener-Policy": ["same-origin"],
    "Cross-Origin-Resource-Policy": ["same-origin"],
    "Set-Cookie": ["sid=abc123; Secure; HttpOnly; SameSite=Lax"],
    "Server": ["nginx"],
}

BAD_HEADERS = {
    "Server": ["Apache/2.4.41 (Ubuntu)"],
    "X-Powered-By": ["Express"],
    "Set-Cookie": ["session=xyz; SameSite=None"],
    "X-XSS-Protection": ["1"],
    "Cache-Control": ["public, max-age=3600"],
}


class TestGrading(unittest.TestCase):
    def test_grade_scale(self):
        self.assertEqual(grade_from_score(100), "A+")
        self.assertEqual(grade_from_score(97), "A+")
        self.assertEqual(grade_from_score(90), "A")
        self.assertEqual(grade_from_score(75), "B")
        self.assertEqual(grade_from_score(60), "C")
        self.assertEqual(grade_from_score(40), "D")
        self.assertEqual(grade_from_score(0), "F")

    def test_full_score_is_aplus(self):
        result = evaluate_headers(GOOD_HEADERS)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.grade, "A+")
        self.assertEqual(result.satisfied, result.total_checks)

    def test_empty_headers_score_zero(self):
        result = evaluate_headers({})
        self.assertEqual(result.score, 0)
        self.assertEqual(result.grade, "F")
        self.assertEqual(result.satisfied, 0)

    def test_bad_site_scores_f(self):
        result = evaluate_headers(BAD_HEADERS)
        self.assertEqual(result.grade, "F")
        self.assertLess(result.score, 40)


class TestIndividualChecks(unittest.TestCase):
    def check_by_name(self, result, name):
        return next(c for c in result.checks if c.name == name)

    def test_hsts_too_short_warns(self):
        r = evaluate_headers({"Strict-Transport-Security": ["max-age=100"]})
        self.assertEqual(self.check_by_name(r, "HSTS").status, "warn")

    def test_hsts_one_day_boundary(self):
        r = evaluate_headers({"Strict-Transport-Security": ["max-age=15551999"]})
        self.assertEqual(self.check_by_name(r, "HSTS").status, "warn")
        r = evaluate_headers({"Strict-Transport-Security": ["max-age=15552000"]})
        self.assertEqual(self.check_by_name(r, "HSTS").status, "good")

    def test_csp_unsafe_inline_warns(self):
        r = evaluate_headers({"Content-Security-Policy":
                              ["default-src 'self'; script-src 'self' 'unsafe-inline'"]})
        self.assertEqual(self.check_by_name(r, "Content-Security-Policy").status, "warn")

    def test_csp_unsafe_eval_in_default_src(self):
        r = evaluate_headers({"Content-Security-Policy": ["default-src 'unsafe-eval'"]})
        self.assertEqual(self.check_by_name(r, "Content-Security-Policy").status, "warn")

    def test_csp_known_good(self):
        r = evaluate_headers({"Content-Security-Policy":
                              ["default-src 'self'; script-src 'self' https://cdn.example"]})
        self.assertEqual(self.check_by_name(r, "Content-Security-Policy").status, "good")

    def test_nosniff_case_insensitive_header_lookup(self):
        r = evaluate_headers({"x-content-type-options": ["nosniff"]})
        self.assertEqual(self.check_by_name(r, "X-Content-Type-Options").status, "good")

    def test_framing_csp_frame_ancestors_counts(self):
        r = evaluate_headers({"Content-Security-Policy":
                              ["default-src 'self'; frame-ancestors 'none'"]})
        self.assertEqual(self.check_by_name(r, "Clickjacking protection").status, "good")

    def test_referrer_policy_lax_value_warns(self):
        r = evaluate_headers({"Referrer-Policy": ["origin-when-cross-origin"]})
        self.assertEqual(self.check_by_name(r, "Referrer-Policy").status, "warn")
        r = evaluate_headers({"Referrer-Policy": ["same-origin"]})
        self.assertEqual(self.check_by_name(r, "Referrer-Policy").status, "good")
        # real-world quirk: sites sending multiple comma-separated policies
        r = evaluate_headers({"Referrer-Policy": ["origin-when-cross-origin, strict-origin-when-cross-origin"]})
        self.assertEqual(self.check_by_name(r, "Referrer-Policy").status, "good")
        r = evaluate_headers({"Referrer-Policy": ["strict-origin-when-cross-origin, origin"]})
        self.assertEqual(self.check_by_name(r, "Referrer-Policy").status, "warn")
        # Server header without digits must NOT trigger the version advisory
        r = evaluate_headers({"Server": ["github.com"]})
        self.assertNotIn("Version disclosure", {a.name for a in r.advisories})
        r = evaluate_headers({"Server": ["nginx/1.24.0"]})
        self.assertIn("Version disclosure", {a.name for a in r.advisories})

    def test_cookie_samesite_none_without_secure_flags(self):
        r = evaluate_headers(BAD_HEADERS)
        c = self.check_by_name(r, "Cookie flags")
        self.assertEqual(c.status, "warn")
        self.assertIn("SameSite=None without Secure", c.detail)

    def test_no_cookies_is_info(self):
        r = evaluate_headers({})
        c = self.check_by_name(r, "Cookie flags")
        self.assertEqual(c.status, "info")
        self.assertEqual(c.weight, 0)
        self.assertEqual(r.score, 0)

    def test_advisories_detected(self):
        r = evaluate_headers(BAD_HEADERS, http_status=200)
        advisory_names = {a.name for a in r.advisories}
        self.assertIn("Version disclosure", advisory_names)
        self.assertIn("Tech disclosure", advisory_names)
        self.assertIn("Legacy header", advisory_names)
        self.assertIn("Caching", advisory_names)

    def test_clean_headers_no_server_advisory(self):
        r = evaluate_headers(GOOD_HEADERS)
        advisory_names = {a.name for a in r.advisories}
        self.assertNotIn("Version disclosure", advisory_names)


class TestFetchHelpers(unittest.TestCase):
    def test_normalize_url_adds_https(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")
        self.assertEqual(normalize_url("http://a.b"), "http://a.b")

    def test_normalize_url_rejects_scheme(self):
        with self.assertRaises(FetchError):
            normalize_url("ftp://example.com")
        with self.assertRaises(FetchError):
            normalize_url("not a url ;;")

    def test_audit_url_unreachable_raises(self):
        with self.assertRaises(FetchError):
            audit_url("https://127.0.0.1:1", timeout=2)


# ---------------------------------------------------------------------------
# Hermetic end-to-end test against a real local HTTP server
# ---------------------------------------------------------------------------

def _make_server(headers, status=200, path_payload=b"ok"):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            for k, v in headers:
                self.send_header(k, v)
            self.send_response(status)
            for k, v in headers:
                pass
            self.end_headers()
        def log_message(self, *a):
            pass
    # Rebuild properly: BaseHTTPRequestHandler requires headers AFTER send_response
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(path_payload)))
            self.end_headers()
            self.wfile.write(path_payload)
        def log_message(self, *a):
            pass
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class TestEndToEnd(unittest.TestCase):
    def test_local_good_site_gets_high_grade(self):
        server = _make_server(
            [(k, v[0]) for k, v in GOOD_HEADERS.items() if k != "Set-Cookie"]
            + [("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")])
        try:
            port = server.server_address[1]
            result = audit_url(f"http://127.0.0.1:{port}/", timeout=5)
            self.assertEqual(result.http_status, 200)
            # HTTP (not HTTPS) means HSTS can't be served — expect slight loss.
            self.assertGreaterEqual(result.score, 85)
            self.assertIn(result.grade, ("A+", "A"))
        finally:
            server.shutdown()

    def test_local_bad_site_gets_f_and_report_lists_fixes(self):
        server = _make_server(list(BAD_HEADERS.items() and
                                   [(k, v[0]) for k, v in BAD_HEADERS.items()]))
        try:
            port = server.server_address[1]
            result = audit_url(f"http://127.0.0.1:{port}/", timeout=5)
            self.assertEqual(result.grade, "F")
            report = text_report(result)
            self.assertIn("Fix these", report)
            self.assertIn("ADVISORIES", report)
        finally:
            server.shutdown()

    def test_json_report_shape(self):
        result = evaluate_headers(GOOD_HEADERS)
        payload = json_report(result)
        encoded = json.dumps(payload)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["grade"], "A+")
        self.assertIn("checks", decoded)
        self.assertIn("advisories", decoded)

    def test_cli_min_grade_exit_codes(self):
        import contextlib, io
        buf = io.StringIO()
        server = _make_server([(k, v[0]) for k, v in BAD_HEADERS.items()
                               if k not in ("Content-Length",)])
        try:
            port = server.server_address[1]
            with contextlib.redirect_stdout(buf):
                rc = run([f"http://127.0.0.1:{port}/", "--min-grade", "B"])
            self.assertEqual(rc, 1)  # F is below B
            with contextlib.redirect_stdout(buf):
                rc = run([f"http://127.0.0.1:{port}/", "--min-grade", "F"])
            self.assertEqual(rc, 0)
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
