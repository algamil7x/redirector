# 🚀 Redirector

> **Advanced Open Redirect Discovery, Bypass & Validation Engine**  
> Built for real-world bug bounty hunting.

![License](https://img.shields.io/badge/license-MIT-yellow)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![Engine](https://img.shields.io/badge/engine-Redirector-orange)
![BugBounty](https://img.shields.io/badge/bugbounty-ready-red)
![Notify](https://img.shields.io/badge/notify-supported-green)

---

## 🔥 Features

- ✅ Advanced Open Redirect Detection & Validation
- ✅ HTTP `301` / `302` / `303` / `307` / `308` Support
- ✅ Redirect Chain Validation
- ✅ Configurable Redirect Depth (`--max-redirects`)
- ✅ Parameter-wise Deep Testing (`--deep`)
- ✅ Dynamic Payload Generation
- ✅ Target-Aware Payloads
- ✅ Smart External Redirect Validation
- ✅ False Positive Reduction
- ✅ HTTP Session Reuse
- ✅ Concurrent Scanning (`--threads`)
- ✅ Headless & Real Browser Engine Support (`--browser`)
- ✅ Automatic WAF & Challenge Fallback (`--auto-browser`)
- ✅ Remote Chrome DevTools Protocol Support (`--cdp`)
- ✅ Thread-Safe Atomic Output Queue for List Mode
- ✅ Compact JSON Output (`--json`)
- ✅ Silent Automation Mode (`-s`)
- ✅ Cookie & Custom Header Support
- ✅ `GET` / `POST` Support
- ✅ Notify Integration

---

## ⚡ Modes

| Mode | Description |
|------|-------------|
| `basic` | Fast basic redirect payloads |
| `custom` | Target-aware bypass payloads |
| `full` | Full advanced payload collection |

### Browser Engine Modes

| Engine Mode | Option | Description |
|-------------|--------|-------------|
| Headless Browser | `--browser` | Forces Playwright headless browser for all targets |
| Auto Fallback | `--auto-browser` | Uses fast HTTP first; falls back to browser on `403`/`503`/WAF |
| Remote CDP | `--cdp` | Connects via CDP to a real browser (e.g. Brave) over SSH tunnel |

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/algamil7x/redirector.git && cd redirector
```

Install requirements:

```bash
python3 -m pip install -r requirements.txt
```

Optional Playwright browser support:

```bash
playwright install chromium
```

Optional Notify support:

```bash
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
```

---

## 🚀 Usage

### Basic Scan

```bash
python3 redirector.py -u "https://target.com/?next=test" -a evil.com -m basic
```

### Custom Scan

```bash
python3 redirector.py -u "https://target.com/?next=test" -a evil.com -m custom
```

### Full Scan

```bash
python3 redirector.py -u "https://target.com/?next=test" -a evil.com -m full
```

### File Scan

```bash
python3 redirector.py -l urls.txt -a evil.com -m full
```

### Authenticated Scan

```bash
python3 redirector.py -u "https://target.com/login?next=test" -a evil.com --cookie "session=abc123" --header "Authorization: Bearer TOKEN"
```

### Deep Parameter-wise Scan

```bash
python3 redirector.py -u "https://target.com/?next=test&return=/home" -a evil.com --deep
```

### Browser Scan (WAF-protected targets)

```bash
python3 redirector.py -u "https://target.com/?next=test" -a evil.com -m basic --browser
```

### Auto-Fallback Browser Scan

```bash
python3 redirector.py -l urls.txt -a evil.com -m full --auto-browser
```

### Remote CDP Scan (Real Brave Browser)

```bash
python3 redirector.py -u "https://target.com/?next=test" -a evil.com -m full --auto-browser --cdp
```

### Redirect Chain Depth

```bash
python3 redirector.py -u "https://target.com/?next=test" -a evil.com --max-redirects 8
```

### Concurrent Scanning

```bash
python3 redirector.py -l urls.txt -a evil.com --threads 20
```

### Silent Mode

```bash
python3 redirector.py -l urls.txt -a evil.com -s
```

### JSON Output

```bash
python3 redirector.py -l urls.txt -a evil.com --json
```

### Compact Help Menu

```bash
python3 redirector.py -h
```

---

## 🌐 Browser Engine & Remote CDP

Redirector features an advanced Browser Engine integrating Playwright and Chrome DevTools Protocol (CDP) for handling modern WAFs, JavaScript-based redirects, and browser challenges (Cloudflare, Akamai, DATADOME).

### Why Remote CDP Exists

Headless browsers are often fingerprinted and blocked by aggressive WAFs. Remote CDP allows Redirector running on a VPS to control a **real, daily-driver desktop browser** (e.g., Brave or Chrome on Windows/macOS) via an SSH reverse tunnel. This bypasses anti-bot detection while maintaining full automation.

### Architecture Diagram

```
Real Brave Browser (Windows)
        │
Remote Debugging (:9222)
        │
SSH Reverse Tunnel
        │
VPS (:9223)
        │
Redirector
        │
Automatic Browser Verification
```

### Execution Modes Comparison

| Feature | HTTP Mode | Browser Mode (`--browser`) | Remote CDP (`--cdp`) |
|---------|-----------|----------------------------|----------------------|
| **Speed** | ⚡ Extremely Fast | 🐢 Moderate | 🐢 Moderate |
| **JS Redirects** | ❌ No | ✅ Yes | ✅ Yes |
| **WAF Bypass** | ⚠️ Basic | 🟡 Medium | 🛡️ Maximum (Real Fingerprint) |
| **Resource Usage** | Low | Medium | Low (Runs on client) |
| **Primary Use Case** | Bulk fast scanning | JS redirects & single targets | Hardened WAF targets |

### Automatic Browser Fallback (`--auto-browser`)

When `--auto-browser` is enabled:
1. Redirector tests targets using fast HTTP client first.
2. If a target returns `403 Forbidden`, `503 Service Unavailable`, or a WAF block page, Redirector automatically passes that specific target to the Browser Engine.
3. The Browser Engine verifies whether an open redirect occurs in a real DOM environment.



## 📄 JSON Output

```json
[
  {
    "url": "<crafted_url_with_payload>",
    "location": "<redirect_destination>",
    "status": "confirmed"
  }
]
```

---

## 📝 Notes

- `--deep` tests one parameter at a time to reduce false negatives.
- `--threads` enables concurrent list scanning (default: **10**).
- `--max-redirects` controls redirect-chain depth (default: **5**).
- `--cdp` connects to Chrome DevTools Protocol at `127.0.0.1:9223` (SSH tunnel).
- `--auto-browser` seamlessly switches to browser verification on HTTP 403/503.
- List mode (`-l`) uses a thread-safe printer queue with stable `[i/total]` indexing.
- `-s` prints confirmed findings only.
- `--json` outputs clean machine-readable JSON.
- `-h` renders a compact single-line help menu.

---

## 📞 Contact

- 🐦 Twitter / X: https://x.com/algamil7x
- 💻 GitHub: https://github.com/algamil7x

---

## ⚠️ Disclaimer

Redirector is intended **only** for authorized security assessments, penetration testing, and bug bounty programs.

Use responsibly and only against systems you have permission to test.

