"""
http_client.py — TLS-impersonated HTTP transport layer.

Uses curl_cffi to send HTTP requests with a Chrome TLS fingerprint,
making the tool indistinguishable from a real browser at the TLS layer.

This module is the ONLY place that knows about the HTTP engine.
The rest of the codebase interacts through HttpClient, which exposes
an API compatible with the requests.Session interface used by
redirector.py (session.request(), session.close()).
"""

from curl_cffi.requests import Session


# ==========================================
# Default Browser Headers
# ==========================================

# Full Chrome header set. These are merged with any user-supplied
# headers. User-supplied headers win on conflict.

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/136.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "sec-ch-ua": (
        '"Chromium";v="136", '
        '"Google Chrome";v="136", '
        '"Not.A/Brand";v="99"'
    ),
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}


# ==========================================
# HttpClient
# ==========================================

class HttpClient:
    """
    Drop-in HTTP transport that impersonates Chrome's TLS fingerprint.

    Exposes .request() and .close() with the same signature that
    redirector.py already uses with requests.Session, so the swap
    is transparent to the caller.
    """

    def __init__(self, cookies=None, headers=None):
        """
        Create a new TLS-impersonated session.

        Args:
            cookies: Optional dict of cookies to attach to every request.
            headers: Optional dict of user-supplied headers.
                     These are merged on top of the default browser
                     header set (user wins on key conflict).
        """
        self._session = Session(impersonate="chrome")

        # Start with the full browser header profile
        merged_headers = dict(DEFAULT_HEADERS)

        # User-supplied headers override defaults
        if headers:
            merged_headers.update(headers)

        self._session.headers.update(merged_headers)

        # Attach cookies if provided
        if cookies:
            self._session.cookies.update(cookies)

    def request(
        self,
        method,
        url,
        allow_redirects=False,
        timeout=8,
        verify=False,
        cookies=None,
        headers=None,
        **kwargs
    ):
        """
        Send an HTTP request through the TLS-impersonated session.

        This method signature is intentionally compatible with
        requests.Session.request() so the rest of the codebase
        does not need to change its calling conventions.

        Args:
            method:          HTTP method ("GET", "POST", etc.)
            url:             Target URL.
            allow_redirects: Follow redirects automatically (default False).
            timeout:         Request timeout in seconds.
            verify:          Verify TLS certificates (default False).
            cookies:         Per-request cookies (merged with session cookies).
            headers:         Per-request headers (merged with session headers).
            **kwargs:        Absorbed for forward compatibility.

        Returns:
            Response object with .status_code, .headers, .url attributes.
        """
        return self._session.request(
            method=method,
            url=url,
            allow_redirects=allow_redirects,
            timeout=timeout,
            verify=verify,
            cookies=cookies,
            headers=headers,
        )

    def close(self):
        """Close the underlying session and release resources."""
        self._session.close()
