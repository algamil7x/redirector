from urllib.parse import urlparse



# ==========================================
# Normalize Location
# ==========================================

def normalize_location(location):

    if not location:
        return ""

    location = location.strip()

    # browser parser confusion normalization
    location = location.replace("\\", "/")

    # fix malformed schemes
    if location.startswith("https:") and not location.startswith("https://"):
        location = location.replace("https:", "https://", 1)

    if location.startswith("http:") and not location.startswith("http://"):
        location = location.replace("http:", "http://", 1)

    return location



# ==========================================
# Extract Hostname
# ==========================================

def extract_hostname(url):

    try:

        parsed = urlparse(url)

        return parsed.hostname

    except:

        return None



# ==========================================
# External Redirect Validation
# ==========================================

def is_external_redirect(location, attacker_domain):

    location = normalize_location(location)

    if not location:
        return False

    # Ignore relative redirects
    if location.startswith("/"):
        return False

    hostname = extract_hostname(location)

    if not hostname:
        return False

    hostname = hostname.lower()

    attacker_domain = attacker_domain.lower()

    # exact or subdomain match only
    return (
        hostname == attacker_domain
        or hostname.endswith("." + attacker_domain)
    )