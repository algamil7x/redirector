"""
waf_detector.py — WAF & Bot Challenge Detection Module.

Analyzes HTTP responses and page titles/content to identify whether a target
is serving a WAF block or JavaScript challenge page (e.g. Cloudflare Turnstile).
"""

# Common headers indicative of WAF / bot mitigation
WAF_HEADERS = [
    "cf-mitigated",
    "cf-ray",
    "x-cdn",
    "x-datadome",
    "x-incapsula-waf",
]

# Body & title text signals indicative of WAF / JavaScript challenge pages
CHALLENGE_KEYWORDS = [
    "just a moment...",
    "attention required!",
    "cloudflare",
    "challenge-platform",
    "turnstile",
    "ddos-guard",
    "incapsula",
    "datadome",
    "access denied",
    "security check",
    "enable javascript",
]


def is_waf_response(status_code, headers, body=""):
    """
    Check if an HTTP response indicates a WAF block or JS challenge.

    Args:
        status_code: HTTP status integer (e.g. 403, 503)
        headers: dict-like HTTP response headers
        body: str snippet of the response body

    Returns:
        (is_blocked: bool, reason: str)
    """

    if status_code in (403, 503):

        # Check headers for Cloudflare / WAF mitigation flags
        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}

        if "cf-mitigated" in headers_lower:
            return True, f"Cloudflare mitigation challenge (status {status_code})"

        if "cf-ray" in headers_lower and status_code in (403, 503):
            return True, f"Cloudflare WAF block (status {status_code})"

        if "server" in headers_lower and "cloudflare" in headers_lower["server"]:
            return True, f"Cloudflare server block (status {status_code})"

        # Check body text keywords
        body_lower = body.lower()
        for keyword in CHALLENGE_KEYWORDS:
            if keyword in body_lower:
                return True, f"WAF/Challenge signal detected: '{keyword}' (status {status_code})"

        return True, f"HTTP {status_code} Forbidden/Service Unavailable"

    return False, ""


def is_browser_challenge_page(title="", url="", body=""):
    """
    Check if Playwright landed on a WAF challenge or block page.

    Args:
        title: Page title string
        url: Page URL string
        body: HTML body text snippet

    Returns:
        (is_challenge: bool, reason: str)
    """

    title_lower = title.lower() if title else ""
    body_lower = body.lower() if body else ""
    url_lower = url.lower() if url else ""

    if "just a moment..." in title_lower or "attention required" in title_lower:
        return True, "Cloudflare challenge page active (title check)"

    if "__cf_chl" in url_lower or "cdn-cgi/challenge-platform" in url_lower:
        return True, "Cloudflare challenge URL active"

    for keyword in ["turnstile", "challenge-platform", "cf-turnstile"]:
        if keyword in body_lower:
            return True, f"Challenge widget detected in DOM ('{keyword}')"

    return False, ""
