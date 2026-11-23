# HTTP/TLS Probe

A single-file Python CLI that checks a URL one layer at a time: DNS, TCP, TLS, HTTP and an optional JSON body check. It stops at the first layer that fails and returns an exit code that names that layer, so a failing health check points straight at DNS, the network path, the certificate or the application.

It uses only the Python standard library.

## What it checks

The checks run in this order. The first failure ends the run.

1. **DNS.** Resolves the host and lists every IPv4 and IPv6 address returned.
2. **TCP.** Opens a connection to the host and port and reports the connect time in milliseconds.
3. **TLS** (https URLs only). Completes a handshake and reports the certificate issuer, the DNS names in the subjectAltName list (the text output shows the first five) and the days left before expiry.
4. **HTTP.** Sends the request and checks the status code against an allow list (200 and 204 by default). Redirects are followed unless `--no-follow` is set.
5. **JSON** (only with `--expect-json`). Fetches the URL again with GET, parses the body and checks that every key and value in the expected snippet is present. Nested objects and lists are compared element by element. Extra keys in the response are allowed.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | DNS resolution failed |
| 2 | TCP connect failed |
| 3 | TLS handshake or certificate check failed |
| 4 | HTTP request failed or the status code is not in the allow list |
| 5 | The JSON body did not match `--expect-json` |

## Requirements

Python 3 with the standard library. No packages to install.

## Usage

```bash
chmod +x http_tls.py
./http_tls.py --url https://example.com/
```

Example output:

```text
[PASS] DNS: Resolved example.com → 104.20.23.154, 172.66.147.243, 2606:4700:10::6814:179a, 2606:4700:10::ac42:93f3
[PASS] TCP connect: Connected tcp/443 in 35.8 ms
[PASS] TLS handshake: TLS OK; issuer: countryName=US, organizationName=SSL Corporation, commonName=Cloudflare TLS Issuing ECC CA 3; SANs: example.com, *.example.com; expires in 32 days
[PASS] HTTP: HTTP 200; followed redirects
Overall: PASS
```

More examples:

```bash
# Check a JSON health endpoint
./http_tls.py --url https://example.com/health --expect-json '{"ok": true}'

# Send extra headers and treat a redirect as success
./http_tls.py --url https://api.example.com/v1/ping --headers 'Authorization:Bearer X;X-Env:prod' --no-follow --allow-status 200,301,302

# Trust a private CA for an internal service
./http_tls.py --url https://internal.service.local --ca-file /path/to/org-root.pem

# Machine-readable output for scripts and CI
./http_tls.py --url https://example.com/ --output json
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | required | Target URL. http and https are supported. |
| `--method` | `GET` | HTTP method for the HTTP step. The JSON step always uses GET. |
| `--timeout` | `6.0` | Timeout in seconds for each network step. |
| `--no-follow` | off | Do not follow redirects. A 3xx status then has to be in `--allow-status` to pass. |
| `--insecure` | off | Turn off certificate and hostname verification. The TLS step still runs, but issuer, SANs and expiry are not reported in this mode. |
| `--ca-file` | none | PEM bundle to trust instead of the system roots. |
| `--headers` | none | Extra request headers as `'Key:Value;Key2:Value2'`. |
| `--expect-json` | none | JSON snippet that must be contained in the response body. |
| `--allow-status` | `200,204` | Comma-separated list of status codes that count as a pass. |
| `--output` | `text` | `text` for one line per step, or `json` for a full report with per-step details. |

The JSON report includes the overall result, the exit code and one object per step with fields such as the resolved addresses, the TCP connect time, the certificate details, the HTTP status and a preview of the body.

## How it works

The TCP, TLS and HTTP steps each open their own connection, so a failure is attributed to the layer that caused it. DNS uses `socket.getaddrinfo`, TCP uses `socket.create_connection`, TLS wraps a fresh socket with an `ssl` context and reads the peer certificate, and HTTP goes through `urllib.request` with the same TLS settings.
