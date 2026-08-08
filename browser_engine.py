"""
browser_engine.py — Playwright-based browser engine for redirect testing.

Supports three execution modes:
  1. Local Playwright   — Ephemeral headless Chromium (default)
  2. Persistent Profile — Chromium with user data directory
  3. Remote CDP         — Connects to a real browser via Chrome DevTools Protocol
"""

from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

from waf_detector import is_browser_challenge_page

BROWSER_TIMEOUT = 15000
DEFAULT_CDP_ENDPOINT = "http://127.0.0.1:9223"


class BrowserEngine:
    """
    Chromium browser engine supporting ephemeral, persistent-profile,
    and remote CDP modes. Each instance must be used from the thread
    that created it (Playwright sync_api is thread-affine).
    """

    def __init__(self, user_data_dir=None, cdp_endpoint=None):
        """
        Launch Playwright and connect to a browser.

        Args:
            user_data_dir: Optional path to a Chromium user profile directory.
                           Enables persistent-profile mode.
            cdp_endpoint:  Optional CDP WebSocket endpoint URL.
                           Enables remote CDP mode (takes priority over user_data_dir).
        """
        self._user_data_dir = user_data_dir
        self._cdp_endpoint = cdp_endpoint
        self._playwright = sync_playwright().start()

        if self._cdp_endpoint:
            # Remote CDP Mode — connect to a real browser over DevTools Protocol
            self._mode = "cdp"
            self._browser = self._playwright.chromium.connect_over_cdp(
                self._cdp_endpoint
            )
            self._browser_context = None
        elif self._user_data_dir:
            # Persistent Profile Mode
            self._mode = "persistent"
            self._browser_context = self._playwright.chromium.launch_persistent_context(
                user_data_dir=self._user_data_dir,
                headless=True
            )
            self._browser = None
        else:
            # Standard Ephemeral Browser Mode
            self._mode = "local"
            self._browser_context = None
            self._browser = self._playwright.chromium.launch(
                headless=True
            )

    @property
    def mode_label(self):
        """Human-readable label for the active engine mode."""
        labels = {
            "cdp": "Remote CDP",
            "persistent": "Persistent Profile",
            "local": "Local Chromium",
        }
        return labels.get(self._mode, self._mode)

    def test_url(self, url, attacker_domain, timeout=None):
        """
        Navigate to a target URL and evaluate if a redirect to attacker_domain occurs.

        Returns:
            dict with keys:
                redirected: bool
                final_url: str
                is_challenge: bool
                reason: str
                error: bool
        """
        if timeout is None:
            timeout = BROWSER_TIMEOUT

        if self._mode == "persistent":
            context = self._browser_context
            page = context.new_page()
            created_context = False
        elif self._mode == "cdp":
            # CDP: create a fresh context on the remote browser
            context = self._browser.new_context()
            page = context.new_page()
            created_context = True
        else:
            # Local ephemeral
            context = self._browser.new_context()
            page = context.new_page()
            created_context = True

        try:
            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=timeout
            )

            final_url = page.url
            title = page.title()
            body_snippet = ""

            try:
                body_snippet = page.content()[:2000]
            except Exception:
                pass

            # Check if landed on WAF/challenge page
            is_challenge, challenge_reason = is_browser_challenge_page(
                title=title,
                url=final_url,
                body=body_snippet
            )

            redirected = _is_attacker_domain(
                final_url,
                attacker_domain
            )

            return {
                "redirected": redirected,
                "final_url": final_url,
                "is_challenge": is_challenge,
                "reason": challenge_reason if is_challenge else "",
                "error": False,
            }

        except Exception as e:
            return {
                "redirected": False,
                "final_url": url,
                "is_challenge": True,
                "reason": f"Browser navigation exception: {type(e).__name__}",
                "error": True,
            }

        finally:
            page.close()
            if created_context:
                context.close()

    def close(self):
        """Clean up Playwright resources."""
        if self._mode == "persistent" and self._browser_context:
            self._browser_context.close()
        elif self._mode == "cdp" and self._browser:
            # Disconnect from remote browser (does not kill the browser)
            self._browser.close()
        elif self._browser:
            self._browser.close()

        self._playwright.stop()


def _is_attacker_domain(final_url, attacker_domain):
    """Check if hostname matches attacker_domain (exact or subdomain match)."""
    try:
        parsed = urlparse(final_url)
        hostname = parsed.hostname
        if not hostname:
            return False

        hostname = hostname.lower()
        attacker_domain = attacker_domain.lower()

        return (
            hostname == attacker_domain
            or hostname.endswith("." + attacker_domain)
        )
    except Exception:
        return False
