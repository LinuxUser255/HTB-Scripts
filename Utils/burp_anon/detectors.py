"""Regexes and small helpers used by the anonymizer."""

from __future__ import annotations

import ipaddress
import math
import re

RE_PRIVKEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----",
    re.S,
)

# Well-known credential formats. Each becomes [SECRET_n].
DEFAULT_SECRET_PATTERNS = [
    r"(?<![A-Za-z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}(?![A-Za-z0-9])",  # AWS key id
    r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{30,}",  # GitHub
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}",  # GitLab
    r"xox[abprs]-[A-Za-z0-9-]{10,}",  # Slack
    r"AIza[0-9A-Za-z_-]{35}",  # Google API
    r"(?<![A-Za-z0-9])ya29\.[A-Za-z0-9_-]{20,}",  # Google OAuth
    r"(?<![A-Za-z0-9])(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,}",  # Stripe
    r"(?<![A-Za-z0-9])sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}",  # OpenAI/Anthropic
    r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}",
    r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",  # SendGrid
    r"(?<![A-Za-z0-9])sq0(?:atp|csp)-[A-Za-z0-9_-]{20,}",  # Square
    r"(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![A-Za-z0-9])",  # Twilio
    r"(?<![A-Za-z0-9])\d{8,10}:AA[A-Za-z0-9_-]{33}",  # Telegram bot
    r"(?<![A-Za-z0-9])EAACEdEose0cBA[A-Za-z0-9]+",  # Facebook
    r"(?<![A-Za-z0-9])dapi[0-9a-f]{32}",  # Databricks
    r"(?<![A-Za-z0-9])hvs\.[A-Za-z0-9_-]{20,}",  # Vault
]

RE_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"
)
RE_URL = re.compile(r"(?<![A-Za-z0-9])(?:https?|wss?|ftp)://[^\s\"'<>\\]+", re.I)
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}")
RE_HOST = re.compile(
    r"(?<![\w@.\-])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w\-])", re.I
)
RE_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?!\.?\d)")
RE_IPV6 = re.compile(r"(?<![:\w])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?![:\w])")
RE_UUID = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])"
)
RE_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
RE_SSN = re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])")
RE_PHONE = re.compile(r"(?<![\w])(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\w])")

# TLDs accepted when a hostname is found in free text (not in a Host header).
# Deliberately excludes file-extension look-alikes (js, md, py, sh, pl, rs, so, ps).
KNOWN_TLDS = set("""
com net org io co uk de fr au ca us gov edu mil info biz app dev cloud ai me eu nl se no dk fi ch at
es it jp cn in br ru be ie nz za mx ar tv cc xyz tech online site store shop local internal corp lan
home localdomain intra intranet priv private ly to gg ws pro name mobi asia tel travel jobs coop aero
post bank insurance health law legal finance capital page host space website digital agency solutions
services systems network media group company global world life live news today link click top vip
pt gr cz hu ro bg hr sk si lt lv ee ua by kz tr il sa ae qa kw eg ng ke ma tn id my sg th vn ph kr tw
hk pk bd lk np cl pe ve uy bo ec cr pa do gt cu is lu li mc mt cy int
""".split())

# Second-level public suffixes: foo.co.uk -> base is foo.co.uk, not co.uk
SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go", "nom", "mil"}


def luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def valid_ipv4(s: str) -> bool:
    try:
        return all(0 <= int(p) <= 255 for p in s.split("."))
    except ValueError:
        return False


def is_private_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast
    )


def valid_ipv6(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv6Address)
    except ValueError:
        return False


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_BLOB_CHARS = re.compile(r"^[A-Za-z0-9+/=_\-.]+$")


def looks_like_blob(s: str, min_len: int = 20) -> bool:
    """Opaque high-entropy value (base64 token, random id) that is not a path/word."""
    if len(s) < min_len or s.startswith("/") or not _BLOB_CHARS.match(s):
        return False
    if not (
        any(c.isdigit() for c in s) and any(c.islower() for c in s) and any(c.isupper() for c in s)
    ):
        return False
    return entropy(s) >= 3.5


def is_binary(text: str) -> bool:
    if "\x00" in text:
        return True
    sample = text[:4096]
    if not sample:
        return False
    bad = sum(1 for c in sample if ord(c) < 32 and c not in "\r\n\t")
    return bad / len(sample) > 0.05
