# Fatah2

```
 ███████╗ █████╗ ████████╗ █████╗ ██╗  ██╗██████╗
 ██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║  ██║╚════██╗
 █████╗  ███████║   ██║   ███████║███████║ █████╔╝
 ██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══██║██╔═══╝
 ██║     ██║  ██║   ██║   ██║  ██║██║  ██║███████╗
 ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

 Advanced Recon Suite · v1.0.0
 Crafted by Pr0fessor SnApe
```

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> ⚠️ **For authorized security assessments only.**
> Obtain written permission before scanning any domain you do not own.

---

## One-command install

```bash
git clone https://github.com/yourname/fatah2.git
cd fatah2
bash install.sh
```

That's it. `install.sh` auto-detects your distro (Kali, Parrot, Arch,
Ubuntu/Debian, Fedora), installs all Go tools, sets up a Python virtualenv,
and registers the global `fatah2` command.

---

## Usage — just enter a domain

### Interactive mode (recommended for new users)
```bash
fatah2
```
Fatah2 prints the banner, asks for a target domain, scan depth, and
output format, then runs automatically. No flags needed.

### Direct mode
```bash
fatah2 -d example.com
```

### All options
```bash
fatah2 -d example.com --depth deep --format json,html,txt
fatah2 -d example.com --depth quick -c 100
fatah2 -d example.com --api-keys configs/api_keys.json
```

### REST API server
```bash
fatah2 serve --port 8080
# Docs: http://localhost:8080/api/v1/docs
```

---

## Scan depth

| Depth    | Tools active                          | Time      |
|----------|---------------------------------------|-----------|
| quick    | Passive only (Subfinder + Assetfinder)| 1–3 min   |
| standard | Passive + DNS brute + HTTP probe      | 5–15 min  |
| deep     | All tools + Amass active + Katana d=4 | 30–90 min |

---

## Project structure

```
fatah2/
├── fatah2.py               ← entry point (banner + wizard + CLI)
├── install.sh              ← one-command cross-distro installer
├── requirements.txt
├── setup.py
│
├── src/
│   ├── core/
│   │   ├── orchestrator.py ← 6-stage async pipeline
│   │   └── target.py       ← domain validation
│   ├── scanners/
│   │   ├── base.py         ← BaseScanner abstract class
│   │   ├── subfinder.py
│   │   ├── sublist3r.py
│   │   ├── assetfinder.py
│   │   ├── amass.py
│   │   ├── katana.py       ← endpoint crawler
│   │   └── dns_brute.py    ← massdns / dnspython brute-force
│   ├── enrichment/
│   │   ├── dns_history.py  ← SecurityTrails + HackerTarget
│   │   ├── http_probe.py   ← httpx binary / Python fallback
│   │   └── whois_enricher.py
│   ├── scoring/
│   │   └── risk_scorer.py  ← heuristic AI risk engine
│   ├── api/
│   │   └── app.py          ← FastAPI REST interface
│   └── utils/
│       ├── deduplicator.py
│       └── reporter.py     ← JSON / TXT / HTML reports
│
├── configs/
│   ├── default.yaml
│   ├── resolvers.txt
│   ├── api_keys.example.json
│   └── wordlists/subdomains.txt
│
├── reports/                ← scan output (git-ignored)
│
└── tests/
    ├── conftest.py
    ├── unit/test_core.py
    └── integration/test_pipeline.py
```

---

## Adding API keys (optional)

```bash
cp configs/api_keys.example.json configs/api_keys.json
# Edit configs/api_keys.json with your keys
fatah2 -d example.com --api-keys configs/api_keys.json
```

| Key              | Source         | Unlocks                   |
|------------------|----------------|---------------------------|
| securitytrails   | SecurityTrails | Historical DNS records     |
| virustotal       | VirusTotal     | Passive DNS / history      |
| shodan           | Shodan         | Port / service data        |
| censys_id/secret | Censys         | Certificate transparency   |
| github           | GitHub token   | Subdomains in public code  |

---

## Running tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## Contributing

No Contributions needed for this tool
---

## License

MIT — for lawful security research only.
Crafted by **Pr0fessor SnApe**.
