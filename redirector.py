import argparse
import requests
import urllib3
import subprocess

from urllib.parse import (
    urlparse,
    parse_qs,
    urlencode,
    urlunparse
)

from payloads import generate_payloads
from validators import is_external_redirect

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

# ==========================================
# Colors
# ==========================================

RESET = "\033[0m"

ORANGE = "\033[38;5;208m"
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"

TIMEOUT = 8

# ==========================================
# Smart Auth Detection
# ==========================================

AUTH_KEYWORDS = [
    "login",
    "signin",
    "auth",
    "oauth",
    "session",
    "connect",
    "account"
]

# ==========================================
# Notify
# ==========================================

def send_notify(message):

    try:

        subprocess.run(
            ["notify"],
            input=message.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    except:
        pass


# ==========================================
# Smart Auth Usage
# ==========================================

def should_use_auth(url):

    lower = url.lower()

    for keyword in AUTH_KEYWORDS:

        if keyword in lower:
            return True

    return False


# ==========================================
# Cookie Parser
# ==========================================

def parse_cookie_string(cookie_string):

    cookies = {}

    if not cookie_string:
        return cookies

    parts = cookie_string.split(";")

    for part in parts:

        if "=" not in part:
            continue

        key, value = part.strip().split("=", 1)

        cookies[key] = value

    return cookies


# ==========================================
# Header Parser
# ==========================================

def parse_headers(header_list):

    headers = {}

    if not header_list:
        return headers

    for item in header_list:

        if ":" not in item:
            continue

        key, value = item.split(":", 1)

        headers[key.strip()] = value.strip()

    return headers


# ==========================================
# Replace Params
# ==========================================

def replace_query_values(url, payload):

    parsed = urlparse(url)

    query = parse_qs(parsed.query)

    if not query:
        return None

    new_query = {}

    for key in query:
        new_query[key] = payload

    encoded = urlencode(
        new_query,
        doseq=True
    )

    final = parsed._replace(query=encoded)

    return urlunparse(final)


# ==========================================
# Help Menu
# ==========================================

def custom_help():

    print(f"""{BOLD}{ORANGE}

╔══════════════════════════════════════════════════════╗
║                 Redirector Help Menu                ║
╚══════════════════════════════════════════════════════╝

{RESET}

{CYAN}[ TARGET OPTIONS ]{RESET}

  {YELLOW}-u, --url{RESET}
      Single URL target

  {YELLOW}-l, --list{RESET}
      File containing URLs


{CYAN}[ REQUIRED ]{RESET}

  {YELLOW}-a, --attacker{RESET}
      External redirect domain


{CYAN}[ PAYLOAD MODES ]{RESET}

  {GREEN}basic{RESET}
      5 basic redirect payloads

  {GREEN}custom{RESET}
      24 target-aware bypass payloads

  {GREEN}full{RESET}
      31 advanced payloads


{CYAN}[ AUTHENTICATION ]{RESET}

  {YELLOW}--cookie{RESET}
      Add session cookies

  {YELLOW}--header{RESET}
      Add custom headers

  {YELLOW}-X, --method{RESET}
      HTTP method (GET / POST)


{CYAN}[ OUTPUT & NOTIFICATIONS ]{RESET}

  {YELLOW}-n, --notify{RESET}
      Send confirmed findings to notify

  {YELLOW}-s, --silent{RESET}
      Silent mode (only print confirmed open redirects)


{CYAN}[ EXAMPLES ]{RESET}

{MAGENTA}# Basic Scan{RESET}

python3 redirector.py \\
-u "https://target.com/?next=test" \\
-a evil.com \\
-m basic


{MAGENTA}# Authenticated Scan{RESET}

python3 redirector.py \\
-u "https://target.com/?next=test" \\
-a evil.com \\
-m custom \\
--cookie "session=abc123"


{MAGENTA}# Custom Headers{RESET}

python3 redirector.py \\
-u "https://target.com/?next=test" \\
-a evil.com \\
--header "Authorization: Bearer TOKEN"


{MAGENTA}# Full Scan + Notify{RESET}

python3 redirector.py \\
-l urls.txt \\
-a evil.com \\
-m full \\
-n


{MAGENTA}# Silent Scan (for automation){RESET}

python3 redirector.py \\
-l urls.txt \\
-a evil.com \\
-s

""")


# ==========================================
# Redirect Testing
# ==========================================

def test_redirect(
    url,
    attacker_domain,
    mode="basic",
    notify_enabled=False,
    cookies=None,
    headers=None,
    method="GET",
    silent=False
):

    payloads = generate_payloads(
        url,
        attacker_domain,
        mode
    )

    payload_count = len(payloads)

    if not silent:

        print(
            f"{BLUE}[TARGET]{RESET}   {url}"
        )

        print(
            f"{MAGENTA}[MODE]{RESET}     {mode}"
        )

        print(
            f"{CYAN}[PAYLOADS]{RESET} {payload_count}"
        )

        print(
            f"{YELLOW}[METHOD]{RESET}   {method}"
        )

        if should_use_auth(url):

            print(
                f"{GREEN}[AUTH]{RESET}     Enabled"
            )

        else:

            print(
                f"{RED}[AUTH]{RESET}     Disabled"
            )

    for payload in payloads:

        test_url = replace_query_values(
            url,
            payload
        )

        if not test_url:
            continue

        try:

            use_auth = should_use_auth(url)

            request_cookies = cookies if use_auth else None

            request_headers = headers if use_auth else None

            response = requests.request(
                method=method,
                url=test_url,
                allow_redirects=False,
                timeout=TIMEOUT,
                verify=False,
                cookies=request_cookies,
                headers=request_headers
            )

            location = response.headers.get(
                "Location",
                ""
            )

            if response.status_code in [
                301,
                302,
                307,
                308
            ]:

                if is_external_redirect(
                    location,
                    attacker_domain
                ):

                    finding = (
                        f"\n{RED}[🚨] CONFIRMED OPEN REDIRECT{RESET}\n"
                        f"{CYAN}[URL]{RESET}      {url}\n"
                        f"{YELLOW}[PAYLOAD]{RESET}  {payload}\n"
                        f"{GREEN}[LOCATION]{RESET} {location}\n"
                        f"{MAGENTA}[MODE]{RESET}     {mode}\n"
                    )

                    print(finding)

                    if notify_enabled:
                        send_notify(finding)

                    return True

        except:
            pass

    if not silent:
        print(
            f"{YELLOW}[-] No Open Redirect Detected{RESET}\n"
        )

    return False


# ==========================================
# File Processing
# ==========================================

def process_file(
    file_path,
    attacker_domain,
    mode="basic",
    notify_enabled=False,
    cookies=None,
    headers=None,
    method="GET",
    silent=False
):

    with open(file_path, "r") as f:

        urls = [
            line.strip()
            for line in f
            if line.strip()
        ]

    total = 0

    if not silent:
        print(
            f"{GREEN}[INFO]{RESET} Loaded URLs: {len(urls)}\n"
        )

    for url in urls:

        if not silent:
            print(
                f"{CYAN}[TESTING]{RESET} "
                f"{url}\n"
            )

        if test_redirect(
            url,
            attacker_domain,
            mode,
            notify_enabled,
            cookies,
            headers,
            method,
            silent=silent
        ):

            total += 1

    if not silent:
        print(
            f"\n{GREEN}[✔ ] Confirmed Redirects:{RESET} {total}"
        )


# ==========================================
# Banner
# ==========================================

def banner():

    print(
        f"""{ORANGE}{BOLD}

██████╗ ███████╗██████╗ ██╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║  ██║██║██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝
██╔══██╗██╔══╝  ██║  ██║██║██╔══██╗██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
██║  ██║███████╗██████╔╝██║██║  ██║███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

{RESET}
                {ORANGE}Open Redirect Bypass Engine{RESET}
                   by {BLUE}@algamil7x{RESET}

"""
    )


# ==========================================
# Main
# ==========================================

def main():

    parser = argparse.ArgumentParser(
        add_help=False
    )

    parser.add_argument(
        "-h",
        "--help",
        action="store_true"
    )

    parser.add_argument(
        "-u",
        "--url"
    )

    parser.add_argument(
        "-l",
        "--list"
    )

    parser.add_argument(
        "-a",
        "--attacker"
    )

    parser.add_argument(
        "-m",
        "--mode",
        default="basic",
        choices=[
            "basic",
            "custom",
            "full"
        ]
    )

    parser.add_argument(
        "-n",
        "--notify",
        action="store_true"
    )

    parser.add_argument(
        "-s",
        "--silent",
        action="store_true"
    )

    parser.add_argument(
        "--cookie"
    )

    parser.add_argument(
        "--header",
        action="append"
    )

    parser.add_argument(
        "-X",
        "--method",
        default="GET"
    )

    args = parser.parse_args()

    if not args.silent:
        banner()

    if args.help:

        custom_help()
        return

    if not args.attacker:

        print(
            f"{RED}[!] Missing attacker domain{RESET}"
        )

        print(
            f"{YELLOW}Use -a evil.com{RESET}"
        )

        return

    cookies = parse_cookie_string(
        args.cookie
    )

    headers = parse_headers(
        args.header
    )

    if args.url:

        test_redirect(
            args.url,
            args.attacker,
            args.mode,
            args.notify,
            cookies,
            headers,
            args.method,
            silent=args.silent
        )

    elif args.list:

        process_file(
            args.list,
            args.attacker,
            args.mode,
            args.notify,
            cookies,
            headers,
            args.method,
            silent=args.silent
        )

    else:

        custom_help()


if __name__ == "__main__":

    main()