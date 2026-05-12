# 🚀 Redirector

> Advanced Open Redirect Bypass Engine  
> Built for real-world bug bounty hunting.

![License](https://img.shields.io/badge/license-MIT-yellow)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![Engine](https://img.shields.io/badge/engine-Redirector-orange)
![BugBounty](https://img.shields.io/badge/bugbounty-ready-red)
![Notify](https://img.shields.io/badge/notify-supported-green)
---

## 🔥 Features

- ✅ OAuth Redirect Testing
- ✅ Dynamic Payload Generation
- ✅ Target-Aware Payloads
- ✅ Mixed Bypass Payloads
- ✅ Smart External Redirect Validation
- ✅ False Positive Reduction
- ✅ Custom Headers Support
- ✅ Cookie-Based Session Support
- ✅ GET / POST Support
- ✅ Smart Auth Detection 
- ✅ Notify Integration / Discord Alerts



---

# ⚡ Modes

| Mode | Description |
|------|-------------|
| `basic` | Fast basic redirect payloads |
| `custom` | Target-aware bypass payloads |
| `full` | Full advanced bypass payloads |

---

# 📦 Installation

## Clone Repository

```bash
git clone https://github.com/algamil7x/redirector.git

cd redirector
```

---

## Install Requirements

```bash
sudo apt install python3-requests -y
```

---

## Install Notify (Optional)

```bash
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
```

---

# 🚀 Usage

## Basic Scan

```bash
python3 redirector.py \
-u "https://target.com/?next=test" \
-a evil.com \
-m basic
```

---

## Custom Bypass Scan

```bash
python3 redirector.py \
-u "https://target.com/?next=test" \
-a evil.com \
-m custom
```

---

## Full Advanced Scan

```bash
python3 redirector.py \
-u "https://target.com/?next=test" \
-a evil.com \
-m full
```

---

# 🔐 Authenticated Scanning

## Using Cookies

```bash
python3 redirector.py \
-u "https://target.com/login?next=test" \
-a evil.com \
-m custom \
--cookie "session=abc123"
```

---

## Using Custom Headers

```bash
python3 redirector.py \
-u "https://target.com/oauth?redirect=test" \
-a evil.com \
--header "Authorization: Bearer TOKEN"
```

---

## POST Requests

```bash
python3 redirector.py \
-u "https://target.com/auth" \
-a evil.com \
-X POST
```

---

# 📂 File Scan

```bash
python3 redirector.py \
-l urls.txt \
-a evil.com \
-m full
```

---

# 🔔 Notify Integration

## Send Confirmed Findings to Discord

```bash
python3 redirector.py \
-l urls.txt \
-a evil.com \
-m full \
-n
```

---

# 🧠 Smart Authentication Detection

Redirector automatically detects authentication-related endpoints:

- login
- signin
- oauth
- session
- connect
- auth
- account

Cookies & headers are only used when needed to reduce noise and improve stealth.

---

# 🛡️ False Positive Reduction

Redirector validates:

- External hostname matching
- Real redirect behavior
- Location header analysis
- Redirect status codes
- Target-aware validation

Only confirmed redirects are reported.

---

# 📞 Contact

- 🐦 Twitter/X: [@algamil7x](https://x.com/algamil7x)
- 💻 GitHub: [@algamil7x](https://github.com/algamil7x)

---

# ⚠️ Disclaimer

This tool is intended for authorized security testing and bug bounty programs only.

Use responsibly.