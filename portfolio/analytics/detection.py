import ipaddress
import re
from urllib.parse import urlparse

from django.conf import settings


KNOWN_CRAWLERS = (
    "googlebot", "bingbot", "duckduckbot", "yandexbot", "baiduspider",
    "slurp", "facebookexternalhit", "linkedinbot",
    "claudebot", "anthropic-ai", "gptbot", "chatgpt-user",
    "oai-searchbot", "perplexitybot", "google-extended", "amazonbot",
    "bytespider", "ccbot",
)
AUTOMATION_MARKERS = (
    "curl/", "wget/", "python-requests", "python-httpx", "aiohttp",
    "scrapy", "headlesschrome", "phantomjs", "selenium", "playwright",
    "nikto", "sqlmap", "nmap", "masscan", "go-http-client",
)
SCANNER_PATHS = re.compile(
    r"(?:^|/)(?:\.env|\.git|wp-admin|wp-login\.php|phpmyadmin|adminer|"
    r"xmlrpc\.php|vendor/phpunit|cgi-bin|server-status|actuator|boaform|"
    r"config\.(?:php|json)|\.aws)(?:/|$)",
    re.IGNORECASE,
)


def _is_trusted_proxy(address):
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    for entry in getattr(settings, "ANALYTICS_TRUSTED_PROXIES", []):
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def _valid_ip(value):
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def request_ip(request):
    """Return the client IP without trusting user-controlled forwarding headers."""
    remote = _valid_ip(request.META.get("REMOTE_ADDR"))
    if not _is_trusted_proxy(remote):
        return remote

    cloudflare = _valid_ip(request.META.get("HTTP_CF_CONNECTING_IP"))
    if cloudflare:
        return cloudflare
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0]
    return _valid_ip(forwarded) or remote


def request_location(request):
    remote = _valid_ip(request.META.get("REMOTE_ADDR"))
    if not _is_trusted_proxy(remote):
        return "", ""
    country = request.META.get("HTTP_CF_IPCOUNTRY", "").upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        country = ""
    city = request.META.get("HTTP_CF_IPCITY", "") or request.META.get(
        "HTTP_X_GEO_CITY", ""
    )
    return country, city[:120]


def classify_user_agent(user_agent):
    ua = user_agent.lower()
    if not ua:
        return "Unknown", "Unknown"
    if any(marker in ua for marker in KNOWN_CRAWLERS + AUTOMATION_MARKERS):
        return "Bot", "Bot / automation"
    device = "Mobile" if any(
        marker in ua for marker in ("mobile", "android", "iphone", "ipad")
    ) else "Desktop"
    if "edg/" in ua:
        browser = "Edge"
    elif "firefox/" in ua:
        browser = "Firefox"
    elif "chrome/" in ua or "crios/" in ua:
        browser = "Chrome"
    elif "safari/" in ua:
        browser = "Safari"
    else:
        browser = "Other"
    return device, browser


def assess_request(request, rate):
    ua = request.META.get("HTTP_USER_AGENT", "")[:2000]
    lower_ua = ua.lower()
    path = request.path[:1000]
    reasons = []
    risk = 0
    known_crawler = any(marker in lower_ua for marker in KNOWN_CRAWLERS)
    automated = any(marker in lower_ua for marker in AUTOMATION_MARKERS)

    if known_crawler:
        reasons.append("identified crawler")
        risk += 5
    if automated:
        reasons.append("automation user-agent")
        risk += 45
    if not ua:
        reasons.append("missing user-agent")
        risk += 30
    if not request.META.get("HTTP_ACCEPT"):
        reasons.append("missing accept header")
        risk += 10
    if SCANNER_PATHS.search(path):
        reasons.append("known scanner path")
        risk += 55
    if request.method not in ("GET", "HEAD", "POST", "OPTIONS"):
        reasons.append("unusual HTTP method")
        risk += 20
    threshold = getattr(settings, "ANALYTICS_RATE_LIMIT_PER_MINUTE", 60)
    if rate > threshold:
        reasons.append(f"request burst ({rate}/min)")
        risk += min(45, 25 + (rate - threshold) // 3)

    return {
        "is_bot": known_crawler or automated,
        "known_crawler": known_crawler,
        "scanner": bool(SCANNER_PATHS.search(path)),
        "risk_score": min(100, risk),
        "reason": ", ".join(reasons)[:255],
        "user_agent": ua,
    }


def referrer_host(value):
    if not value:
        return "Direct / unknown"
    try:
        return urlparse(value).hostname or "Direct / unknown"
    except ValueError:
        return "Invalid referrer"
