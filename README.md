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

---

## 🛡️ Validation

Redirector confirms findings using:

- External attacker-controlled destination validation
- HTTP `301` / `302` / `303` / `307` / `308`
- Redirect-chain traversal
- Loop detection
- Deep parameter-wise testing (`--deep`)
- Hostname verification
- Location header validation

Only confirmed open redirects are reported.

---

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
- `-s` prints confirmed findings only.
- `--json` outputs clean machine-readable JSON.

---

## 📞 Contact

- 🐦 Twitter / X: https://x.com/algamil7x
- 💻 GitHub: https://github.com/algamil7x

---

## ⚠️ Disclaimer

Redirector is intended **only** for authorized security assessments, penetration testing, and bug bounty programs.

Use responsibly and only against systems you have permission to test.
