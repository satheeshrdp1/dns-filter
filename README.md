# DNS Filter

This repository contains a small DNS filter/proxy that can block domains (like ad domains) and optionally provide a simple Flask web UI to manage blocked rules.

Features
- Plaintext blocked domains list with exact and suffix/wildcard (`*.example`) rules
- UDP DNS proxy: returns `0.0.0.0` for blocked A queries and forwards allowed queries to an upstream resolver
- Simple Flask-based REST API to view/add/remove rules

Quick start

1. Create a virtualenv and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Edit `config/blocked_domains.txt` to add your blocked domains (one per line). Use `*.example` for suffix matches.

3. Run the DNS filter server (UDP port 5353 by default):

```bash
python -m src.dns_filter.server 5353
```

4. (Optional) Run the web UI at `http://localhost:8080`:

```bash
python web/app.py
```

Notes and security
- Running a UDP server on port 53 requires root privileges; defaults use `5353` for convenience.
- This software is a simple educational example. Don't expose it to untrusted networks without additional hardening.

Examples
- Block `ads.example.com` by adding `ads.example.com` to `config/blocked_domains.txt`.
- Block all subdomains of `tracking.example` by adding `*.tracking.example`.

Testing

Run unit tests:

```bash
pytest -q
```
# dns-filter