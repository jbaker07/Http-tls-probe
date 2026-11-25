"""Tests for http_tls.py.

Every test except the last runs against servers started here on 127.0.0.1, so no internet
access is needed. A throwaway CA and a localhost certificate are made with the openssl
command line tool when the tests start. The TLS tests are skipped if openssl is missing.
The example.com test is skipped when example.com cannot be reached.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_DIR)
import http_tls  # noqa: E402

PROBE = os.path.join(REPO_DIR, "http_tls.py")

HEALTH_BODY = {"ok": True, "build": {"version": "1.2.3", "tags": ["a", "b"]}}

OPENSSL_CONFIG = """
[req]
distinguished_name = dn
[dn]
[ca_ext]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[server_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


class Handler(http.server.BaseHTTPRequestHandler):

    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, HEALTH_BODY)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/health")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/empty":
            self.send_response(204)
            self.end_headers()
        elif self.path == "/text":
            body = b"not json"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/echo":
            headers = {}
            for name, value in self.headers.items():
                headers[name.lower()] = value
            self.send_json(200, headers)
        else:
            self.send_json(404, {"error": "not found"})

    def log_message(self, *args):
        pass


class QuietServer(http.server.ThreadingHTTPServer):
    # Several tests make the client drop the connection on purpose (a failed certificate
    # check, or the probe's TLS step closing right after the handshake). Those resets are
    # expected, so they are not printed.
    def handle_error(self, request, client_address):
        pass


def start_in_thread(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def free_port():
    probe_socket = socket.socket()
    probe_socket.bind(("127.0.0.1", 0))
    port = probe_socket.getsockname()[1]
    probe_socket.close()
    return port


def run_probe(*args, timeout=60):
    started = time.time()
    result = subprocess.run([sys.executable, PROBE] + list(args),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    result.elapsed = time.time() - started
    return result


CERT_DIR = None
SNI_SEEN = []


def setUpModule():
    global CERT_DIR, HTTP_SERVER, HTTPS_SERVER, SILENT_SOCKET
    HTTP_SERVER = start_in_thread(QuietServer(("127.0.0.1", 0), Handler))

    # a TCP listener that accepts and then never answers, for the timeout test
    SILENT_SOCKET = socket.socket()
    SILENT_SOCKET.bind(("127.0.0.1", 0))
    SILENT_SOCKET.listen(8)

    HTTPS_SERVER = None
    if shutil.which("openssl") is None:
        return
    CERT_DIR = tempfile.mkdtemp()
    config_path = os.path.join(CERT_DIR, "openssl.cnf")
    with open(config_path, "w") as f:
        f.write(OPENSSL_CONFIG)

    def openssl(*args):
        subprocess.run(["openssl"] + list(args), cwd=CERT_DIR, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    openssl("req", "-x509", "-config", config_path, "-extensions", "ca_ext", "-newkey", "rsa:2048",
            "-nodes", "-days", "3", "-subj", "/CN=Probe Test CA", "-keyout", "ca.key", "-out", "ca.pem")
    openssl("req", "-new", "-config", config_path, "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=localhost", "-keyout", "server.key", "-out", "server.csr")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
            "-days", "2", "-extfile", config_path, "-extensions", "server_ext", "-out", "server.pem")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(os.path.join(CERT_DIR, "server.pem"), os.path.join(CERT_DIR, "server.key"))

    def remember_sni(ssl_socket, server_name, ssl_context):
        SNI_SEEN.append(server_name)

    context.sni_callback = remember_sni
    server = QuietServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    HTTPS_SERVER = start_in_thread(server)


def tearDownModule():
    HTTP_SERVER.shutdown()
    SILENT_SOCKET.close()
    if HTTPS_SERVER is not None:
        HTTPS_SERVER.shutdown()
    if CERT_DIR:
        shutil.rmtree(CERT_DIR, ignore_errors=True)


def http_url(path):
    return f"http://127.0.0.1:{HTTP_SERVER.server_address[1]}{path}"


def https_url(path):
    return f"https://localhost:{HTTPS_SERVER.server_address[1]}{path}"


def ca_file():
    return os.path.join(CERT_DIR, "ca.pem")


class ParseHeadersTests(unittest.TestCase):

    def test_pairs_are_split_on_semicolons_and_the_first_colon(self):
        self.assertEqual(http_tls.parse_headers("A:1; B : 2;bad;C:x:y;"), {"A": "1", "B": "2", "C": "x:y"})

    def test_nothing_given(self):
        self.assertEqual(http_tls.parse_headers(None), {})


class PlainHttpTests(unittest.TestCase):

    def test_http_url_skips_tls_and_passes(self):
        result = run_probe("--url", http_url("/health"), "--output", "json")
        self.assertEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)
        self.assertTrue(report["overall"])
        self.assertEqual(report["exit_code"], 0)
        names = [step["name"] for step in report["steps"]]
        self.assertEqual(names, ["DNS", "TCP connect", "HTTP"])

    def test_204_is_allowed_by_default(self):
        result = run_probe("--url", http_url("/empty"))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[PASS] HTTP: HTTP 204", result.stdout)

    def test_404_exits_4(self):
        result = run_probe("--url", http_url("/missing"))
        self.assertEqual(result.returncode, 4, result.stdout)
        self.assertIn("[FAIL] HTTP: HTTP 404", result.stdout)

    def test_redirect_is_followed(self):
        result = run_probe("--url", http_url("/redirect"))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("HTTP 200; followed redirects", result.stdout)

    def test_redirect_without_follow_exits_4(self):
        result = run_probe("--url", http_url("/redirect"), "--no-follow")
        self.assertEqual(result.returncode, 4, result.stdout)
        self.assertIn("HTTP 302; no-follow", result.stdout)

    def test_redirect_without_follow_passes_when_allowed(self):
        result = run_probe("--url", http_url("/redirect"), "--no-follow", "--allow-status", "200,302")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_unsupported_scheme_exits_4(self):
        result = run_probe("--url", f"ftp://127.0.0.1:{HTTP_SERVER.server_address[1]}/")
        self.assertEqual(result.returncode, 4, result.stdout)
        self.assertIn("Unsupported scheme: ftp", result.stdout)


class JsonExpectTests(unittest.TestCase):

    def test_matching_snippet_passes(self):
        result = run_probe("--url", http_url("/health"), "--expect-json", '{"ok": true}')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[PASS] JSON expect: JSON expectation satisfied", result.stdout)

    def test_nested_objects_and_lists_are_compared_element_by_element(self):
        result = run_probe("--url", http_url("/health"), "--expect-json", '{"build": {"version": "1.2.3", "tags": ["a"]}}')
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_wrong_value_exits_5_and_names_the_path(self):
        result = run_probe("--url", http_url("/health"), "--expect-json", '{"ok": false}')
        self.assertEqual(result.returncode, 5, result.stdout)
        self.assertIn("JSON expectation failed at: $.ok", result.stdout)

    def test_missing_nested_key_names_the_path(self):
        result = run_probe("--url", http_url("/health"), "--expect-json", '{"build": {"commit": "abc"}}')
        self.assertEqual(result.returncode, 5, result.stdout)
        self.assertIn("$.build.commit", result.stdout)

    def test_body_that_is_not_json_exits_5(self):
        result = run_probe("--url", http_url("/text"), "--expect-json", '{"ok": true}')
        self.assertEqual(result.returncode, 5, result.stdout)
        self.assertIn("Body is not valid JSON", result.stdout)

    def test_bad_expect_json_argument_exits_5(self):
        result = run_probe("--url", http_url("/health"), "--expect-json", "{not json")
        self.assertEqual(result.returncode, 5, result.stdout)
        self.assertIn("--expect-json is not valid JSON", result.stdout)

    def test_extra_headers_reach_the_server(self):
        result = run_probe("--url", http_url("/echo"), "--headers", "X-Probe: yes; X-Env:test",
                           "--expect-json", '{"x-probe": "yes", "x-env": "test", "user-agent": "http-tls-probe/0.2"}')
        self.assertEqual(result.returncode, 0, result.stdout)


class FailureLayerTests(unittest.TestCase):

    def test_unknown_host_exits_1(self):
        # .invalid is reserved by RFC 6761 and never resolves
        result = run_probe("--url", "https://no-such-host.invalid/")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("[FAIL] DNS", result.stdout)

    def test_closed_port_exits_2(self):
        result = run_probe("--url", f"http://127.0.0.1:{free_port()}/")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("[FAIL] TCP connect", result.stdout)

    def test_server_that_never_answers_times_out_at_the_http_step(self):
        result = run_probe("--url", f"http://127.0.0.1:{SILENT_SOCKET.getsockname()[1]}/", "--timeout", "1")
        self.assertEqual(result.returncode, 4, result.stdout)
        self.assertIn("[PASS] TCP connect", result.stdout)
        self.assertIn("[FAIL] HTTP: HTTP request failed", result.stdout)
        self.assertLess(result.elapsed, 15)


@unittest.skipIf(shutil.which("openssl") is None, "openssl is not installed, TLS tests skipped")
class TlsTests(unittest.TestCase):

    def test_trusted_private_ca_passes_and_reports_the_certificate(self):
        result = run_probe("--url", https_url("/health"), "--ca-file", ca_file())
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("issuer: commonName=Probe Test CA", result.stdout)
        self.assertIn("SANs: localhost", result.stdout)
        self.assertIn("expires in 1 days", result.stdout)

    def test_private_ca_not_trusted_exits_3(self):
        result = run_probe("--url", https_url("/health"))
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn("certificate verify failed", result.stdout)

    def test_insecure_passes_and_still_sends_sni(self):
        del SNI_SEEN[:]
        result = run_probe("--url", https_url("/health"), "--insecure")
        self.assertEqual(result.returncode, 0, result.stdout)
        # the TLS step and the HTTP step each make one TLS connection, and both must name the host
        self.assertGreaterEqual(len(SNI_SEEN), 2)
        self.assertEqual(SNI_SEEN, ["localhost"] * len(SNI_SEEN))
        self.assertIn("certificate not verified (--insecure)", result.stdout)

    def test_tls_to_a_plain_http_port_exits_3(self):
        result = run_probe("--url", f"https://127.0.0.1:{HTTP_SERVER.server_address[1]}/")
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn("[FAIL] TLS handshake", result.stdout)

    def test_json_check_over_tls_with_private_ca(self):
        result = run_probe("--url", https_url("/health"), "--ca-file", ca_file(), "--expect-json", '{"ok": true}')
        self.assertEqual(result.returncode, 0, result.stdout)


def internet_reachable():
    try:
        with socket.create_connection(("example.com", 443), timeout=3):
            return True
    except OSError:
        return False


class InternetTests(unittest.TestCase):

    @unittest.skipUnless(internet_reachable(), "example.com:443 is not reachable, internet test skipped")
    def test_example_com_passes(self):
        result = run_probe("--url", "https://example.com/")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Overall: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
