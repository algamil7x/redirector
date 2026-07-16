import argparse
import json
import requests
import urllib3
import subprocess
import threading

from concurrent.futures import ThreadPoolExecutor, as_completed

from urllib.parse import (
    urlparse,
    parse_qs,
    urlencode,
    urlunparse,
    urljoin
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
# Session Helper
# ==========================================


def create_session():

    return requests.Session()


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


def generate_test_urls(url, payload, deep=False):

    if not deep:

        test_url = replace_query_values(url, payload)

        return [test_url] if test_url else []

    parsed = urlparse(url)

    query = parse_qs(parsed.query)

    if not query:
        return []

    test_urls = []

    for target_key in query:

        new_query = {}

        for key, values in query.items():

            if key == target_key:
                new_query[key] = payload
            else:
                new_query[key] = values

        encoded = urlencode(
            new_query,
            doseq=True
        )

        final = parsed._replace(query=encoded)

        test_urls.append(urlunparse(final))

    return list(dict.fromkeys(test_urls))


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

  {YELLOW}--deep{RESET}
      Mutate one query parameter at a time


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

  {YELLOW}--json{RESET}
      Output confirmed findings as compact JSON array

{CYAN}[ REDIRECT CHAIN ]{RESET}

  {YELLOW}--max-redirects{RESET}
      Max redirects to follow (default: 5)


{CYAN}[ PERFORMANCE ]{RESET}

  {YELLOW}--threads{RESET}
      Number of worker threads for list scans (default: 10)


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
    silent=False,
    json_output=False,
    max_redirects=5,
    deep=False,
    session=None
):

    payloads = generate_payloads(
        url,
        attacker_domain,
        mode
    )

    created_session = False

    if session is None:

        session = create_session()
        created_session = True

    payload_count = len(payloads)

    if not silent and not json_output:

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

        print(
            f"{CYAN}[MAX-REDIRECTS]{RESET} {max_redirects}"
        )

        if cookies or headers:

            print(
                f"{GREEN}[AUTH]{RESET}     Enabled"
            )

        else:

            print(
                f"{RED}[AUTH]{RESET}     Disabled"
            )

    for payload in payloads:

        test_urls = generate_test_urls(
            url,
            payload,
            deep=deep
        )

        if not test_urls:
            continue

        for test_url in test_urls:

            try:

                request_cookies = cookies if cookies else None

                request_headers = headers if headers else None

                current_url = test_url
                current_method = method
                redirects_followed = 0
                visited_urls = set()

                while True:

                    if current_url in visited_urls:
                        break

                    visited_urls.add(current_url)

                    response = session.request(
                        method=current_method,
                        url=current_url,
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
                        303,
                        307,
                        308
                    ] and location:

                        if is_external_redirect(
                            location,
                            attacker_domain
                        ):

                            if json_output:

                                finding = {
                                    "url": test_url,
                                    "location": location,
                                    "status": "confirmed"
                                }

                                if notify_enabled:
                                    send_notify(json.dumps(finding))

                                if created_session:
                                    session.close()

                                return finding

                            if silent:

                                finding = f"{test_url} {location}"

                            else:

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

                            if created_session:
                                session.close()

                            return True

                        if redirects_followed >= max_redirects:
                            break

                        next_url = urljoin(
                            current_url,
                            location
                        )

                        if not next_url:
                            break

                        current_url = next_url

                        if response.status_code == 303:
                            current_method = "GET"

                        redirects_followed += 1
                        continue

                    break

            except:
                pass

    if created_session:

        session.close()

    if not silent and not json_output:
        print(
            f"{YELLOW}[-] No Open Redirect Detected{RESET}\n"
        )

    return None if json_output else False


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
    silent=False,
    json_output=False,
    max_redirects=5,
    deep=False,
    threads=10
):

    with open(file_path, "r") as f:

        urls = [
            line.strip()
            for line in f
            if line.strip()
        ]

    total = 0
    findings = []

    if threads < 1:
        threads = 1

    if not silent and not json_output:
        print(
            f"{GREEN}[INFO]{RESET} Loaded URLs: {len(urls)}"
        )
        print(
            f"{CYAN}[THREADS]{RESET} {threads}\n"
        )

    if threads == 1:

        shared_session = create_session()

        try:

            for url in urls:

                if not silent and not json_output:
                    print(
                        f"{CYAN}[TESTING]{RESET} "
                        f"{url}\n"
                    )

                result = test_redirect(
                    url,
                    attacker_domain,
                    mode,
                    notify_enabled,
                    cookies,
                    headers,
                    method,
                    silent=silent,
                    json_output=json_output,
                    max_redirects=max_redirects,
                    deep=deep,
                    session=shared_session
                )

                if json_output:

                    if result:
                        findings.append(result)

                elif result:

                    total += 1

        finally:

            shared_session.close()

    else:

        if not silent and not json_output:

            for url in urls:
                print(
                    f"{CYAN}[TESTING]{RESET} "
                    f"{url}\n"
                )

        thread_local = threading.local()
        sessions = []
        sessions_lock = threading.Lock()

        def get_thread_session():

            if not hasattr(thread_local, "session"):

                thread_local.session = create_session()

                with sessions_lock:
                    sessions.append(thread_local.session)

            return thread_local.session

        def scan_url(url):

            return test_redirect(
                url,
                attacker_domain,
                mode,
                notify_enabled,
                cookies,
                headers,
                method,
                silent=silent,
                json_output=json_output,
                max_redirects=max_redirects,
                deep=deep,
                session=get_thread_session()
            )

        with ThreadPoolExecutor(max_workers=threads) as executor:

            future_to_url = {
                executor.submit(scan_url, url): url
                for url in urls
            }

            for future in as_completed(future_to_url):

                result = future.result()

                if json_output:

                    if result:
                        findings.append(result)

                elif result:

                    total += 1

        for session in sessions:
            session.close()

    if not silent and not json_output:
        print(
            f"\n{GREEN}[✔ ] Confirmed Redirects:{RESET} {total}"
        )

    return findings if json_output else None


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

    parser.add_argument(
        "--json",
        action="store_true"
    )

    parser.add_argument(
        "--max-redirects",
        type=int,
        default=5
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=10
    )

    parser.add_argument(
        "--deep",
        action="store_true"
    )

    args = parser.parse_args()

    if args.max_redirects < 0:
        args.max_redirects = 0

    if args.threads < 1:
        args.threads = 1

    if not args.silent and not args.json:
        banner()

    if args.help:

        custom_help()
        return

    if not args.attacker:

        if args.json:
            print("[]")

        elif not args.silent:
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

        if args.json:

            result = test_redirect(
                args.url,
                args.attacker,
                args.mode,
                args.notify,
                cookies,
                headers,
                args.method,
                silent=True,
                json_output=True,
                max_redirects=args.max_redirects,
                deep=args.deep
            )

            findings = [result] if result else []
            print(json.dumps(findings, separators=(",", ":")))

        else:

            test_redirect(
                args.url,
                args.attacker,
                args.mode,
                args.notify,
                cookies,
                headers,
                args.method,
                silent=args.silent,
                max_redirects=args.max_redirects,
                deep=args.deep
            )

    elif args.list:

        if args.json:

            findings = process_file(
                args.list,
                args.attacker,
                args.mode,
                args.notify,
                cookies,
                headers,
                args.method,
                silent=True,
                json_output=True,
                max_redirects=args.max_redirects,
                deep=args.deep,
                threads=args.threads
            )

            print(json.dumps(findings, separators=(",", ":")))

        else:

            process_file(
                args.list,
                args.attacker,
                args.mode,
                args.notify,
                cookies,
                headers,
                args.method,
                silent=args.silent,
                json_output=False,
                max_redirects=args.max_redirects,
                deep=args.deep,
                threads=args.threads
            )

    else:

        custom_help()


if __name__ == "__main__":

    main()