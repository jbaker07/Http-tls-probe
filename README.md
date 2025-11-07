# HTTP/TLS Probe (MVP)
Dependency-free CLI: DNS → TCP → TLS → HTTP → JSON.

## Quick start

chmod +x http_tls.py
./http_tls.py --url https://example.com/health
./http_tls.py --url https://expired.badssl.com --insecure
