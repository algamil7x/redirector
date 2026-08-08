import argparse
import json
import subprocess
import threading
import queue
from dataclasses import dataclass
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
from http_client import HttpClient
from waf_detector import is_waf_response
from browser_engine import DEFAULT_CDP_ENDPOINT

try:
    from browser_engine import BrowserEngine
    BROWSER_AVAILABLE = True
except ImportError:
    BROWSER_AVAILABLE = False

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
║                 Redirector Help Menu                 ║
╚══════════════════════════════════════════════════════╝{RESET}

{CYAN}[ TARGET OPTIONS ]{RESET}
  {YELLOW}-u, --url{RESET}                Single URL target
  {YELLOW}-l, --list{RESET}               File containing URLs
  {YELLOW}-a, --attacker{RESET}           External redirect domain (Required)

{CYAN}[ PAYLOAD MODES ]{RESET}
  {YELLOW}-m, --mode{RESET}               Payload mode: basic (5), custom (24), full (31) (default: basic)
  {YELLOW}--deep{RESET}                   Mutate one query parameter at a time

{CYAN}[ AUTHENTICATION & HEADERS ]{RESET}
  {YELLOW}--cookie{RESET}                 Add session cookies
  {YELLOW}--header{RESET}                 Add custom headers
  {YELLOW}-X, --method{RESET}             HTTP method (GET / POST) (default: GET)

{CYAN}[ OUTPUT & NOTIFICATIONS ]{RESET}
  {YELLOW}-n, --notify{RESET}             Send confirmed findings to notify
  {YELLOW}-s, --silent{RESET}             Silent mode (output confirmed redirects only)
  {YELLOW}--json{RESET}                   Output confirmed findings as JSON array

{CYAN}[ ENGINE & PERFORMANCE ]{RESET}
  {YELLOW}--max-redirects{RESET}          Max redirects to follow (default: 5)
  {YELLOW}--threads{RESET}                Worker threads for list scans (default: 10)

{CYAN}[ BROWSER ENGINE ]{RESET}
  {YELLOW}--browser{RESET}                Use headless browser for all targets
  {YELLOW}--auto-browser{RESET}           Auto-fallback to browser on 403/503 / WAF
  {YELLOW}--cdp{RESET}                    Remote Chrome DevTools (127.0.0.1:9223)
  {YELLOW}--browser-profile{RESET}        Path to Chromium user data directory

{CYAN}[ EXAMPLES ]{RESET}
  {MAGENTA}# Basic Scan{RESET}
  python3 redirector.py -u "https://target.com/?next=test" -a evil.com -m basic

  {MAGENTA}# Authenticated Scan{RESET}
  python3 redirector.py -u "https://target.com/?next=test" -a evil.com -m custom --cookie "session=abc123"

  {MAGENTA}# Custom Headers{RESET}
  python3 redirector.py -u "https://target.com/?next=test" -a evil.com --header "Authorization: Bearer TOKEN"

  {MAGENTA}# Full Scan + Notify{RESET}
  python3 redirector.py -l urls.txt -a evil.com -m full -n

  {MAGENTA}# Silent Scan (for automation){RESET}
  python3 redirector.py -l urls.txt -a evil.com -s

  {MAGENTA}# Browser Scan (WAF-protected targets){RESET}
  python3 redirector.py -u "https://target.com/?next=test" -a evil.com -m basic --browser

  {MAGENTA}# Auto-fallback to browser on 403{RESET}
  python3 redirector.py -l urls.txt -a evil.com -m full --auto-browser

  {MAGENTA}# Remote CDP (real Brave browser via SSH tunnel){RESET}
  python3 redirector.py -u "https://target.com/?next=test" -a evil.com -m full --auto-browser --cdp
""")


# ==========================================
# Finding Reporter
# ==========================================

def _report_finding(
    url,
    test_url,
    payload,
    location,
    mode,
    json_output,
    silent,
    notify_enabled,
    browser_tag=False,
    status="confirmed",
    reason="",
    return_string=False
):

    tag = " [BROWSER]" if browser_tag else ""

    if status == "manual_required":

        if json_output:

            finding = {
                "original_url": url,
                "url": test_url,
                "status": "manual_required",
                "reason": reason
            }

            if notify_enabled:
                send_notify(json.dumps(finding))

            return finding

        if silent:

            finding = f"{test_url} [MANUAL_REQUIRED] {reason}"

        else:

            finding = (
                f"{YELLOW}[⚠️ ] MANUAL VERIFICATION REQUIRED{tag}{RESET}\n"
                f"{CYAN}[PAYLOAD]{RESET}  {test_url}\n"
                f"{RED}[REASON]{RESET}   {reason}"
            )

        if not return_string:
            print(f"\n{finding}")

        if notify_enabled:
            send_notify(finding)

        return finding

    if json_output:

        finding = {
            "original_url": url,
            "url": test_url,
            "location": location,
            "status": "confirmed",
            "payload": payload,
            "mode": mode
        }

        if notify_enabled:
            send_notify(json.dumps(finding))

        return finding

    if silent:

        finding = f"{test_url}"

    else:

        finding = (
            f"{RED}[🚨] CONFIRMED OPEN REDIRECT{tag}{RESET}\n"
            f"{CYAN}[PAYLOAD]{RESET}  {test_url}"
        )

    if not return_string:
        print(f"\n{finding}")

    if notify_enabled:
        send_notify(finding)

    return finding if return_string else True


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
    session=None,
    browser_engine=None,
    use_browser=False,
    auto_browser=False,
    return_block=False
):

    payloads = generate_payloads(
        url,
        attacker_domain,
        mode
    )

    created_session = False

    if not use_browser and session is None:

        session = HttpClient(
            cookies=cookies,
            headers=headers
        )
        created_session = True

    payload_count = len(payloads)

    if not silent and not json_output and not return_block:

        if browser_engine:

            print(
                f"{GREEN}[ENGINE]{RESET}   {browser_engine.mode_label}"
            )

            print()

        print(
            f"{BLUE}[TARGET]{RESET}   {url}"
        )

        print(
            f"{MAGENTA}[MODE]{RESET}     {mode}"
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

            # ---- Browser-only mode ----

            if use_browser and browser_engine:

                result = browser_engine.test_url(
                    test_url,
                    attacker_domain
                )

                if result.get("redirected"):

                    finding = _report_finding(
                        url, test_url, payload,
                        result["final_url"], mode,
                        json_output, silent,
                        notify_enabled,
                        browser_tag=True,
                        return_string=return_block
                    )

                    if created_session:
                        session.close()

                    if return_block and not json_output:
                        return True, finding
                    return finding

                if result.get("is_challenge"):

                    finding = _report_finding(
                        url, test_url, payload,
                        result["final_url"], mode,
                        json_output, silent,
                        notify_enabled,
                        browser_tag=True,
                        status="manual_required",
                        reason=result.get("reason", "Browser challenge blocked"),
                        return_string=return_block
                    )

                    if created_session:
                        session.close()

                    if return_block and not json_output:
                        return False, finding
                    return finding

                continue

            # ---- HTTP mode ----

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

                            finding = _report_finding(
                                url, test_url, payload,
                                location, mode,
                                json_output, silent,
                                notify_enabled,
                                return_string=return_block
                            )

                            if created_session:
                                session.close()

                            if return_block and not json_output:
                                return True, finding
                            return finding

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

                    # Non-redirect response: inspect for WAF / Challenge

                    is_waf, waf_reason = is_waf_response(
                        response.status_code,
                        response.headers,
                        response.text[:2000] if hasattr(response, "text") else ""
                    )

                    if is_waf:

                        if auto_browser and browser_engine:

                            browser_result = browser_engine.test_url(
                                test_url,
                                attacker_domain
                            )

                            if browser_result.get("redirected"):

                                finding = _report_finding(
                                    url, test_url, payload,
                                    browser_result["final_url"],
                                    mode, json_output, silent,
                                    notify_enabled,
                                    browser_tag=True,
                                    return_string=return_block
                                )

                                if created_session:
                                    session.close()

                                if return_block and not json_output:
                                    return True, finding
                                return finding

                            if browser_result.get("is_challenge"):

                                finding = _report_finding(
                                    url, test_url, payload,
                                    browser_result["final_url"],
                                    mode, json_output, silent,
                                    notify_enabled,
                                    browser_tag=True,
                                    status="manual_required",
                                    reason=browser_result.get("reason", waf_reason),
                                    return_string=return_block
                                )

                                if created_session:
                                    session.close()

                                if return_block and not json_output:
                                    return False, finding
                                return finding

                        # HTTP WAF detected and browser didn't solve it / is off

                        finding = _report_finding(
                            url, test_url, payload,
                            "", mode, json_output, silent,
                            notify_enabled,
                            status="manual_required",
                            reason=waf_reason,
                            return_string=return_block
                        )

                        if created_session:
                            session.close()

                        if return_block and not json_output:
                            return False, finding
                        return finding

                    break

            except:
                pass

    if created_session:

        session.close()

    if json_output:
        return None

    if return_block:
        return False, f"{RED}[-] No Open Redirect Detected{RESET}"

    if not silent:
        print(
            f"\n{RED}[-] No Open Redirect Detected{RESET}\n"
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
    silent=False,
    json_output=False,
    max_redirects=5,
    deep=False,
    threads=10,
    use_browser=False,
    auto_browser=False,
    cdp_endpoint=None,
    user_data_dir=None
):

    with open(file_path, "r") as f:
        urls = [
            line.strip()
            for line in f
            if line.strip()
        ]

    total = 0
    total_lock = threading.Lock()
    findings = []
    findings_lock = threading.Lock()

    if threads < 1:
        threads = 1

    if not silent and not json_output:
        print(f"{GREEN}[INFO]{RESET} Loaded URLs: {len(urls)}")
        print(f"{CYAN}[THREADS]{RESET} {threads}\n")

        result_queue = queue.Queue()

        def printer_worker():
            while True:
                item = result_queue.get()
                if item is None:
                    break
                idx, total_count, url, block = item
                output_str = f"[{idx}/{total_count}] -> {url}\n{block}"
                print(output_str, flush=True)

        printer_thread = threading.Thread(target=printer_worker, daemon=True)
        printer_thread.start()

    indexed_urls = list(enumerate(urls, start=1))

    if threads == 1:
        shared_session = None
        local_engine = None
        if not use_browser:
            shared_session = HttpClient(
                cookies=cookies,
                headers=headers
            )
        if use_browser or auto_browser:
            local_engine = BrowserEngine(
                user_data_dir=user_data_dir,
                cdp_endpoint=cdp_endpoint
            )

        try:
            for idx, url in indexed_urls:
                if json_output:
                    result = test_redirect(
                        url, attacker_domain, mode, notify_enabled,
                        cookies, headers, method, silent=silent, json_output=True,
                        max_redirects=max_redirects, deep=deep, session=shared_session,
                        browser_engine=local_engine, use_browser=use_browser, auto_browser=auto_browser
                    )
                    if result:
                        findings.append(result)
                else:
                    is_confirmed, block = test_redirect(
                        url, attacker_domain, mode, notify_enabled,
                        cookies, headers, method, silent=silent, json_output=False,
                        max_redirects=max_redirects, deep=deep, session=shared_session,
                        browser_engine=local_engine, use_browser=use_browser, auto_browser=auto_browser,
                        return_block=True
                    )
                    if is_confirmed:
                        total += 1
                    if not silent:
                        result_queue.put((idx, len(urls), url, block))
        finally:
            if shared_session:
                shared_session.close()
            if local_engine:
                local_engine.close()

    else:
        thread_local = threading.local()

        def get_thread_session():
            if use_browser:
                return None
            if not hasattr(thread_local, "session"):
                thread_local.session = HttpClient(
                    cookies=cookies,
                    headers=headers
                )
            return thread_local.session

        def get_thread_engine():
            if not (use_browser or auto_browser):
                return None
            if not hasattr(thread_local, "engine"):
                thread_local.engine = BrowserEngine(
                    user_data_dir=user_data_dir,
                    cdp_endpoint=cdp_endpoint
                )
            return thread_local.engine

        def scan_url(idx_url):
            nonlocal total
            idx, url = idx_url
            if json_output:
                res = test_redirect(
                    url, attacker_domain, mode, notify_enabled,
                    cookies, headers, method, silent=silent, json_output=True,
                    max_redirects=max_redirects, deep=deep, session=get_thread_session(),
                    browser_engine=get_thread_engine(), use_browser=use_browser, auto_browser=auto_browser
                )
                if res:
                    with findings_lock:
                        findings.append(res)
            else:
                is_confirmed, block = test_redirect(
                    url, attacker_domain, mode, notify_enabled,
                    cookies, headers, method, silent=silent, json_output=False,
                    max_redirects=max_redirects, deep=deep, session=get_thread_session(),
                    browser_engine=get_thread_engine(), use_browser=use_browser, auto_browser=auto_browser,
                    return_block=True
                )
                if is_confirmed:
                    with total_lock:
                        total += 1
                if not silent:
                    result_queue.put((idx, len(urls), url, block))

        def scan_batch(batch):
            """Process a batch of URLs, closing thread-local resources before returning."""
            try:
                for idx_url in batch:
                    scan_url(idx_url)
            finally:
                if hasattr(thread_local, "engine"):
                    thread_local.engine.close()
                if hasattr(thread_local, "session"):
                    thread_local.session.close()

        # Partition URLs into per-worker batches
        num_workers = min(threads, len(indexed_urls))
        batches = [[] for _ in range(num_workers)]
        for i, idx_url in enumerate(indexed_urls):
            batches[i % num_workers].append(idx_url)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(scan_batch, batch) for batch in batches]
            for future in as_completed(futures):
                future.result()

    if not silent and not json_output:
        result_queue.put(None)
        printer_thread.join()
        print(f"\n{GREEN}[✔ ] Confirmed Redirects:{RESET} {total}", flush=True)

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

    parser.add_argument(
        "--browser",
        action="store_true"
    )

    parser.add_argument(
        "--auto-browser",
        action="store_true"
    )

    parser.add_argument(
        "--browser-profile"
    )

    parser.add_argument(
        "--cdp",
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

    # Browser engine lifecycle

    use_browser = args.browser
    auto_browser = args.auto_browser
    browser_profile = args.browser_profile
    use_cdp = args.cdp

    if use_cdp and not (use_browser or auto_browser):
        auto_browser = True

    need_browser = use_browser or auto_browser or browser_profile
    cdp_endpoint = DEFAULT_CDP_ENDPOINT if use_cdp else None

    if need_browser and not BROWSER_AVAILABLE:

        if not args.silent:
            print(
                f"{RED}[!] Playwright is required "
                f"for --browser / --auto-browser / --cdp{RESET}"
            )
            print(
                f"{YELLOW}Install with: pip install "
                f"playwright && playwright install "
                f"chromium{RESET}"
            )

        return

    if args.url:

        browser_engine = None
        if need_browser:
            browser_engine = BrowserEngine(
                user_data_dir=browser_profile,
                cdp_endpoint=cdp_endpoint
            )

        try:

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
                    deep=args.deep,
                    browser_engine=browser_engine,
                    use_browser=use_browser,
                    auto_browser=auto_browser
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
                    deep=args.deep,
                    browser_engine=browser_engine,
                    use_browser=use_browser,
                    auto_browser=auto_browser
                )

        finally:

            if browser_engine:
                browser_engine.close()

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
                threads=args.threads,
                use_browser=use_browser,
                auto_browser=auto_browser,
                cdp_endpoint=cdp_endpoint,
                user_data_dir=browser_profile
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
                threads=args.threads,
                use_browser=use_browser,
                auto_browser=auto_browser,
                cdp_endpoint=cdp_endpoint,
                user_data_dir=browser_profile
            )

    else:

        custom_help()


if __name__ == "__main__":

    main()