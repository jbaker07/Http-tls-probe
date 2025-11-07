#!/usr/bin/env python3
"""
HTTP/TLS Probe — Minimal, dependency-free diagnostics

Checks performed (in order):
 1) DNS resolution for host from URL
 2) TCP connectivity to host:port
 3) TLS handshake (issuer, SANs, days to expiry)
 4) HTTP request (status, redirects)
 5) Optional JSON body validation (keys/values present)

Exit codes
  0 = all checks passed
  1 = DNS failure
  2 = TCP connect failure
  3 = TLS handshake/cert failure
  4 = HTTP request failure (non-2xx unless --allow-status)
  5 = JSON expectation failure

Usage examples
  probe.py --url https://example.com/health --expect-json '{"ok": true}'
  probe.py --url https://expired.badssl.com --insecure
  probe.py --url https://api.example.com/v1/ping --method GET --headers 'Authorization:Bearer X;X-Env:prod' --no-follow
  probe.py --url https://internal.service.local --ca-file /path/to/org-root.pem

Author: Jermaine Baker (resume project)
"""

import argparse
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
from http.client import HTTPResponse
from typing import Any, Dict, List, Optional, Tuple

PASS = "PASS"
FAIL = "FAIL"

DEFAULT_UA = "http-tls-probe/0.2"

class Result:
    def __init__(self):
        self.steps: List[Dict[str, Any]] = []
        self.exit_code: int = 0

    def add(self, name: str, ok: bool, details: Dict[str, Any]):
        self.steps.append({"name": name, "ok": ok, **details})
        if not ok and self.exit_code == 0:
            # First failure defines exit code mapping
            self.exit_code = details.get("exit_code", 1)

    def ok(self) -> bool:
        return all(s["ok"] for s in self.steps)

    def print_text(self):
        for s in self.steps:
            status = PASS if s["ok"] else FAIL
            msg = s.get("message") or ""
            print(f"[{status}] {s['name']}: {msg}")
        overall = PASS if self.ok() else FAIL
        print(f"Overall: {overall}")

    def print_json(self):
        print(json.dumps({
            "overall": self.ok(),
            "exit_code": self.exit_code,
            "steps": self.steps
        }, indent=2))


def parse_headers(header_str: Optional[str]) -> Dict[str, str]:
    """Parse --headers 'K:V;K2:V2' into a dict. Whitespace around keys/values is stripped."""
    out: Dict[str, str] = {}
    if not header_str:
        return out
    for pair in header_str.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            # Ignore malformed entries silently
            continue
        k, v = pair.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def build_ssl_context(insecure: bool, ca_file: Optional[str]) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_file:
        # Use a context that trusts only the provided CA file in addition to system roots
        ctx = ssl.create_default_context(cafile=ca_file)
        return ctx
    return ssl.create_default_context()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="HTTP/TLS probe (dependency-free)")
    p.add_argument("--url", required=True, help="Target URL (e.g., https://example.com/health)")
    p.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    p.add_argument("--timeout", type=float, default=6.0, help="Socket/HTTP timeout seconds (default 6.0)")
    p.add_argument("--no-follow", action="store_true", help="Do not follow redirects")
    p.add_argument("--insecure", action="store_true", help="Skip certificate verification")
    p.add_argument("--ca-file", default=None, help="Custom CA bundle/PEM to trust for TLS")
    p.add_argument("--headers", default=None, help="Additional request headers as 'K:V;K2:V2'")
    p.add_argument("--expect-json", default=None, help="JSON snippet to expect in body (keys/values must be present)")
    p.add_argument("--allow-status", default="200,204", help="Comma list of acceptable HTTP status codes")
    p.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    return p.parse_args()


def dns_check(host: str, port: int, timeout: float) -> Tuple[bool, str, List[str]]:
    try:
        # getaddrinfo may block; set global default timeout for this call
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addrs = sorted({info[4][0] for info in infos})
        return True, f"Resolved {host} → {', '.join(addrs)}", addrs
    except Exception as e:
        return False, f"DNS resolution failed for {host}: {e}", []


def tcp_check(host: str, port: int, timeout: float) -> Tuple[bool, str, Optional[float]]:
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            elapsed = (time.time() - start) * 1000.0
            return True, f"Connected tcp/{port} in {elapsed:.1f} ms", elapsed
    except Exception as e:
        return False, f"TCP connect to {host}:{port} failed: {e}", None


def tls_check(host: str, port: int, timeout: float, insecure: bool, ca_file: Optional[str]) -> Tuple[bool, str, Dict[str, Any]]:
    ctx = build_ssl_context(insecure, ca_file)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=None if insecure else host) as ssock:
                cert = ssock.getpeercert()
                # Extract issuer, subjectAltName, notAfter
                issuer = ", ".join("{}={}".format(k, v) for k, v in cert.get("issuer", [("", "")])[0])
                san_list = [d[1] for d in cert.get("subjectAltName", []) if d[0].lower() == "dns"]
                not_after = cert.get("notAfter")
                days_left = None
                if not_after:
                    try:
                        # Parse as ASN.1 time string
                        expires = ssl.cert_time_to_seconds(not_after)
                        days_left = int((expires - time.time()) / 86400)
                    except Exception:
                        pass
                msg = f"TLS OK; issuer: {issuer or 'unknown'}; SANs: {', '.join(san_list[:5]) or 'none'}; expires in {days_left} days"
                return True, msg, {"issuer": issuer, "sans": san_list, "days_left": days_left}
    except ssl.SSLError as e:
        return False, f"TLS handshake failed: {e}", {}
    except Exception as e:
        return False, f"TLS connection failed: {e}", {}


class NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    https_response = http_response


def http_check(url: str, timeout: float, method: str, allow_status: List[int], follow: bool, insecure: bool, ca_file: Optional[str], extra_headers: Dict[str, str]) -> Tuple[bool, str, Dict[str, Any]]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme: {parsed.scheme}", {}

    ctx = build_ssl_context(insecure, ca_file)

    handlers = [urllib.request.HTTPSHandler(context=ctx)] if parsed.scheme == "https" else []
    if not follow:
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    headers = {"User-Agent": DEFAULT_UA}
    headers.update(extra_headers)

    req = urllib.request.Request(url=url, method=method.upper(), headers=headers)
    try:
        with opener.open(req, timeout=timeout) as resp:  # typeHTTPResponse
            status = int(resp.status)
            loc = resp.headers.get("Location")
            body_preview = resp.read(2048)
            ok = status in allow_status
            message = f"HTTP {status}; {'followed redirects' if follow else 'no-follow'}"
            meta = {
                "status": status,
                "location": loc,
                "body_preview": body_preview[:200].decode(errors="replace")
            }
            if not ok:
                return False, message, meta
            return True, message, meta
    except urllib.error.HTTPError as e:
        meta = {"status": e.code, "reason": e.reason, "headers": dict(e.headers)}
        return (e.code in allow_status, f"HTTP {e.code} {e.reason}", meta)
    except Exception as e:
        return False, f"HTTP request failed: {e}", {}


def json_expect_check(url: str, timeout: float, insecure: bool, ca_file: Optional[str], expect_str: str, extra_headers: Dict[str, str]) -> Tuple[bool, str, Dict[str, Any]]:
    parsed = urllib.parse.urlparse(url)
    ctx = build_ssl_context(insecure, ca_file)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)) if parsed.scheme == "https" else urllib.request.build_opener()

    headers = {"User-Agent": DEFAULT_UA, "Accept": "application/json"}
    headers.update(extra_headers)
    req = urllib.request.Request(url=url, method="GET", headers=headers)

    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                data = json.loads(raw.decode())
            except Exception as e:
                return False, f"Body is not valid JSON: {e}", {"body_preview": raw[:200].decode(errors="replace")}
            try:
                expect = json.loads(expect_str)
            except Exception as e:
                return False, f"--expect-json is not valid JSON: {e}", {}
            missing = []
            def deep_contains(hay: Any, needle: Any, path: str = "$") -> None:
                if isinstance(needle, dict):
                    if not isinstance(hay, dict):
                        missing.append(path)
                        return
                    for k, v in needle.items():
                        if k not in hay:
                            missing.append(f"{path}.{k}")
                        else:
                            deep_contains(hay[k], v, f"{path}.{k}")
                elif isinstance(needle, list):
                    if not isinstance(hay, list):
                        missing.append(path)
                        return
                    for i, v in enumerate(needle):
                        if i >= len(hay):
                            missing.append(f"{path}[{i}]")
                        else:
                            deep_contains(hay[i], v, f"{path}[{i}]")
                else:
                    if hay != needle:
                        missing.append(path)
            deep_contains(data, expect)
            if missing:
                return False, f"JSON expectation failed at: {', '.join(missing[:5])}", {"expect": expect, "body_preview": json.dumps(data)[:300]}
            return True, "JSON expectation satisfied", {"expect": expect}
    except Exception as e:
        return False, f"Fetch failed during JSON expectation: {e}", {}


def main():
    args = parse_args()
    parsed = urllib.parse.urlparse(args.url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    res = Result()

    # 1) DNS
    ok, msg, addrs = dns_check(host, port, args.timeout)
    res.add("DNS", ok, {"message": msg, "host": host, "addresses": addrs, "exit_code": 1})
    if not ok:
        return finish(res, args.output)

    # 2) TCP
    ok, msg, ms = tcp_check(host, port, args.timeout)
    res.add("TCP connect", ok, {"message": msg, "port": port, "rtt_ms": ms, "exit_code": 2})
    if not ok:
        return finish(res, args.output)

    # 3) TLS (only for https)
    if parsed.scheme == "https":
        ok, msg, meta = tls_check(host, port, args.timeout, args.insecure, args.ca_file)
        res.add("TLS handshake", ok, {"message": msg, **meta, "exit_code": 3})
        if not ok:
            return finish(res, args.output)

    # 4) HTTP
    try:
        allow_status = [int(x.strip()) for x in args.allow_status.split(',') if x.strip()]
    except ValueError:
        allow_status = [200, 204]
    user_headers = parse_headers(args.headers)
    ok, msg, meta = http_check(args.url, args.timeout, args.method, allow_status, not args.no_follow, args.insecure, args.ca_file, user_headers)
    res.add("HTTP", ok, {"message": msg, **meta, "exit_code": 4})
    if not ok:
        return finish(res, args.output)

    # 5) JSON expectation
    if args.expect_json:
        ok, msg, meta = json_expect_check(args.url, args.timeout, args.insecure, args.ca_file, args.expect_json, user_headers)
        res.add("JSON expect", ok, {"message": msg, **meta, "exit_code": 5})

    return finish(res, args.output)


def finish(res: Result, fmt: str) -> None:
    if fmt == "json":
        res.print_json()
    else:
        res.print_text()
    sys.exit(res.exit_code)


if __name__ == "__main__":
    main()
