# Xfweb — The Beast

> Next-generation web application security scanner with AI-powered detection, modern auth testing, and full API coverage.

[![CI](https://github.com/Cazo-Net/Xfweb/actions/workflows/ci.yml/badge.svg)](https://github.com/Cazo-Net/Xfweb/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

---

## What is Xfweb?

Xfweb is a free, open-source web application security scanner that combines the battle-tested detection engine of w3af (190+ plugins) with modern capabilities:

- **HTTP/2 + WebSocket + gRPC** support via `httpx` + `websockets`
- **GraphQL** introspection, batching, depth-limit testing
- **OAuth2/OIDC/JWT** authentication & token manipulation
- **AI-powered** payload generation, anomaly detection, and false positive reduction (OpenAI / Anthropic)
- **SARIF output** for GitHub/GitLab Security tabs
- **Modern web dashboard** (FastAPI + vanilla React)
- **CI/CD ready** with Docker and GitHub Actions

## Quick Start

### Install

```bash
# From GitHub (recommended)
pip install git+https://github.com/Cazo-Net/Xfweb.git

# Or clone and install locally
git clone https://github.com/Cazo-Net/Xfweb.git
cd Xfweb
pip install -e .

# With AI support (OpenAI / Anthropic)
pip install "git+https://github.com/Cazo-Net/Xfweb.git[ai]"

# Install Playwright browsers (required for SPA crawling)
playwright install chromium
```

---

## Usage

### `xfweb scan` — Run a vulnerability scan

```bash
# Basic scan (all plugins)
xfweb scan -t https://example.com

# Scan with a profile
xfweb scan -t https://example.com --profile full_audit
xfweb scan -t https://example.com --profile fast_scan
xfweb scan -t https://example.com --profile owasp_top10
xfweb scan -t https://example.com --profile api_security
xfweb scan -t https://example.com --profile auth_test

# Enable specific plugins only
xfweb scan -t https://example.com --plugins sqli,xss,csrf

# Exclude specific plugins
xfweb scan -t https://example.com --exclude dir_listing,robots_txt

# Enable AI-powered detection
xfweb scan -t https://example.com --enable-ai

# Use a proxy (e.g. Burp Suite)
xfweb scan -t https://example.com --proxy http://127.0.0.1:8080

# Control concurrency and rate limiting
xfweb scan -t https://example.com --max-threads 10 --rate-limit 5.0

# Set output directory and format
xfweb scan -t https://example.com -o ./results -f sarif
xfweb scan -t https://example.com -o ./results -f json
xfweb scan -t https://example.com -o ./results -f html
xfweb scan -t https://example.com -o ./results -f csv

# Verbose logging
xfweb scan -t https://example.com -v

# Full example
xfweb scan -t https://example.com \
  --profile owasp_top10 \
  --proxy http://127.0.0.1:8080 \
  --max-threads 20 \
  --rate-limit 10.0 \
  --enable-ai \
  -o ./my_scan \
  -f sarif \
  -v
```

**Scan options:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | *(required)* | Target URL to scan |
| `--profile` | `-p` | all plugins | Scan profile name |
| `--plugins` | `-P` | all | Comma-separated plugin names |
| `--exclude` | `-x` | none | Comma-separated plugins to skip |
| `--max-threads` | | 30 | Max concurrent requests |
| `--rate-limit` | | 0.0 | Requests/sec (0 = unlimited) |
| `--proxy` | | none | HTTP proxy URL |
| `--output` | `-o` | `xfweb_output` | Output directory |
| `--format` | `-f` | `json` | Output format: `json`, `sarif`, `html`, `csv` |
| `--enable-ai` | | off | Enable AI payload generation |
| `--verbose` | `-v` | off | Verbose logging |

---

### `xfweb serve` — Start the REST API server

```bash
# Start on default port 8080
xfweb serve

# Custom host and port
xfweb serve --host 127.0.0.1 --port 9090

# Dev mode with auto-reload
xfweb serve --reload
```

**Server options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `8080` | Listen port |
| `--reload` | off | Auto-reload on code changes |

Once running, open:
- **Dashboard:** `http://localhost:8080/dashboard`
- **API docs:** `http://localhost:8080/docs`
- **Health check:** `http://localhost:8080/health`

---

### `xfweb crawl` — Map an attack surface

```bash
# Crawl a site and list discovered URLs
xfweb crawl -t https://example.com

# Save crawl results
xfweb crawl -t https://example.com -o ./crawl_results
```

---

### `xfweb plugins` — List available plugins

```bash
# Show all 71 plugins with categories and descriptions
xfweb plugins
```

---

### API Endpoints (when `xfweb serve` is running)

```bash
# Start a scan via API
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "plugins": ["sqli", "xss"]}'

# Check scan status
curl http://localhost:8080/api/v1/scan/{scan_id}

# Get findings
curl http://localhost:8080/api/v1/scan/{scan_id}/findings

# Get findings filtered by severity
curl http://localhost:8080/api/v1/scan/{scan_id}/findings?severity=high

# Export results (json or sarif)
curl http://localhost:8080/api/v1/results/{scan_id}/export?format=sarif

# Stop a running scan
curl -X DELETE http://localhost:8080/api/v1/scan/{scan_id}

# List all plugins
curl http://localhost:8080/api/v1/plugins

# List scan profiles
curl http://localhost:8080/api/v1/profiles

# Health check
curl http://localhost:8080/health

# Real-time updates via WebSocket
wscat -c ws://localhost:8080/ws/scan/{scan_id}
```

---

### Docker

```bash
# Build the image
docker build -t xfweb .

# Run a scan
docker run --rm xfweb scan -t https://example.com -o /results

# Run with a profile
docker run --rm xfweb scan -t https://example.com --profile owasp_top10 -o /results

# Run API server
docker run -p 8080:8080 xfweb serve

# Run with Burp proxy
docker run --rm --network host xfweb scan -t https://example.com --proxy http://127.0.0.1:8080
```

## Plugin Categories

| Category | Count | Key Plugins |
|----------|-------|-------------|
| **audit** | 18 | `sqli`, `xss`, `csrf`, `lfi`, `rfi`, `ssrf`, `xxe`, `os_commanding`, `eval`, `file_upload`, `buffer_overflow`, `format_string`, `redos`, `frontpage`, `htaccess_methods`, `global_redirect`, `response_splitting`, `cors_origin` |
| **crawl** | 11 | `web_spider`, `robots_txt`, `sitemap_xml`, `open_api`, `dir_listing`, `dir_file_bruter`, `playwright_spider`, `google_spider`, `bing_spider`, `dot_ds_store`, `find_backdoors` |
| **grep** | 13 | `csp`, `credit_cards`, `get_emails`, `html_comments`, `password_profiling`, `click_jacking`, `private_ip`, `strange_headers`, `analyze_cookies`, `error_500`, `path_disclosure`, `url_session`, `meta_tags` |
| **infrastructure** | 8 | `server_header`, `fingerprint_os`, `fingerprint_waf`, `allowed_methods`, `detect_reverse_proxy`, `shared_hosting`, `dot_listing` |
| **evasion** | 3 | `rnd_case`, `rnd_hex_encode`, `x_forwarded_for` |
| **output** | 4 | `sarif`, `json_file`, `html_file`, `csv_file` |
| **graphql** | 3 | `graphql_introspection`, `graphql_batching`, `graphql_depth` |
| **websocket** | 1 | `websocket_hijacking` |
| **auth** | 2 | `oauth2_auth`, `jwt_attacks` |
| **bruteforce** | 2 | `basic_auth_brute`, `form_auth_brute` |
| **ai** | 4 | `ai_payload`, `ai_fp_reducer`, `ai_anomaly`, `ai_vuln_chain` |

**Total: 69 plugins** across 12 categories.

## Scan Profiles

| Profile | File | Description |
|---------|------|-------------|
| `full_audit` | `profiles/full_audit.yaml` | Comprehensive scan — all plugins enabled |
| `fast_scan` | `profiles/fast_scan.yaml` | Quick targeted scan — XSS + SQLi only |
| `owasp_top10` | `profiles/owasp_top10.yaml` | OWASP Top 10 focused |
| `api_security` | `profiles/api_security.yaml` | REST + GraphQL + WebSocket API testing |
| `auth_test` | `profiles/auth_test.yaml` | OAuth2/JWT authentication flow testing |

## AI Engine

Xfweb integrates an optional AI engine (`xfweb.ai`) for:

- **Payload generation** — LLM-aware context-specific payloads (SQLi, XSS, LFI, SSRF)
- **Anomaly detection** — Response baseline comparison + deviation scoring
- **False positive reduction** — Pattern analysis with known FP heuristics
- **Vulnerability chaining** — Combining low-severity findings into critical chains

Supports **OpenAI** (`gpt-4o-mini`) and **Anthropic** (`claude-3-5-haiku`). Falls back to built-in payload lists when no API key is configured.

```toml
# pyproject.toml
[tool.xfweb.ai]
provider = "openai"
api_key = "sk-..."
```

## Architecture

```
xfweb/
├── src/xfweb/
│   ├── core/
│   │   ├── controllers/     # Scan orchestration (XfwebCore, Strategy, PluginManager)
│   │   ├── net/             # Async HTTP engine (httpx, HTTP/2, WebSocket)
│   │   ├── data/            # Data models, parsers, KB, FuzzableRequest
│   │   ├── plugins/         # 15 plugin base classes
│   │   └── ui/
│   │       ├── api/         # FastAPI REST + WebSocket server
│   │       ├── dashboard/   # Dark-theme web dashboard (HTML/JS)
│   │       └── console/     # Rich terminal output
│   ├── plugins/             # 69 concrete plugin implementations
│   │   ├── audit/           # SQLi, XSS, CSRF, LFI, SSRF, XXE, ...
│   │   ├── crawl/           # Spider, OpenAPI, Playwright SPA, ...
│   │   ├── grep/            # CSP, credit cards, emails, cookies, ...
│   │   ├── infrastructure/  # Server headers, WAF detection, OS fingerprint
│   │   ├── evasion/         # Case randomization, hex encoding, X-Forwarded-For
│   │   ├── graphql/         # Introspection, batching, depth testing
│   │   ├── websocket/       # WebSocket hijacking
│   │   ├── auth/            # OAuth2, JWT attacks
│   │   ├── bruteforce/      # Basic auth, form auth brute-force
│   │   ├── output/          # SARIF, JSON, HTML, CSV reports
│   │   └── ai/              # AI-powered plugins (payload gen, FP reduction)
│   ├── ai/                  # AI engine core (AnomalyDetector, AiEngine)
│   └── cli/                 # Click CLI entry point
├── profiles/                # Scan profile YAMLs
├── tests/                   # Pytest test suite
├── Dockerfile               # Multi-stage build (Python 3.11-slim)
└── pyproject.toml           # Hatchling build, all dependencies
```

## Development

```bash
# Clone
git clone https://github.com/Cazo-Net/Xfweb.git
cd Xfweb

# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint + type check
ruff check src/ tests/
mypy src/xfweb/
```

## Acknowledgments

Xfweb builds on the foundation of [w3af](https://github.com/andresriancho/w3af) by Andres Riancho. We thank the w3af community for 15+ years of web security research.

## License

GPL v2 or later — see [LICENSE](LICENSE) for details.
