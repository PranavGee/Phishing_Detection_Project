"""
Canonical URL feature extractor for the Phishing Detection Project.

The model is trained on exactly ten columns of `dataset_phishing.csv`:

    url, length_url, length_hostname, ip, nb_dots,
    nb_hyphens, nb_at, nb_qm, nb_and, nb_or

`url` is the identifier, the remaining nine are the model inputs.

Every definition below was reverse-engineered from the dataset itself and
verified against it by `ml/verify_features.py` (agreement is >= 99.9% on all
nine features and exactly 100% on `ip`).  The identical logic is mirrored in
JavaScript in `extension/lib/features.js` so that the browser extension scores
a URL exactly the way the model was trained.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# The nine numeric model inputs, in the order the model expects them.
FEATURE_NAMES = [
    "length_url",
    "length_hostname",
    "ip",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_qm",
    "nb_and",
    "nb_or",
]

# Human readable labels used by the web app / extension explanation panel.
FEATURE_LABELS = {
    "length_url": "Total URL length",
    "length_hostname": "Hostname length",
    "ip": "Raw IP address / long hex token in URL",
    "nb_dots": "Number of dots ( . )",
    "nb_hyphens": "Number of hyphens ( - )",
    "nb_at": "Number of at signs ( @ )",
    "nb_qm": "Number of question marks ( ? )",
    "nb_and": "Number of ampersands ( & )",
    "nb_or": "Number of pipes ( | )",
}

_OCTET = r"([01]?\d\d?|2[0-4]\d|25[0-5])"
# An IPv4 host written directly in the URL, followed by a path separator, or a
# long hexadecimal token (>= 7 hex chars) such as a raw resource id.  This is
# the exact rule used by the dataset's `ip` column (100% agreement, 11430 rows).
_IP_LIKE = re.compile(
    r"(?:(?:%s\.){3}%s/)|(?:(?<![0-9a-fA-F])[0-9a-fA-F]{7,})" % (_OCTET, _OCTET)
)


def normalize_url(url: str) -> str:
    """Trim the URL and give it a scheme so `urlparse` finds the hostname."""
    url = (url or "").strip()
    if url and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return url


def _to_ascii_host(host: str) -> str:
    """Punycode an internationalised hostname, the way a browser resolves it.

    `new URL(...).host` in JavaScript always yields the ASCII (IDNA) form, so
    without this the extension and the web app would compute a different
    `length_hostname` for the same internationalised URL and could disagree on
    the verdict.  Hosts IDNA cannot encode are left alone rather than dropped.
    """
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return host


def get_hostname(url: str) -> str:
    """Hostname without the port, matching the dataset's `length_hostname`."""
    netloc = urlparse(normalize_url(url)).netloc
    if "@" in netloc:                      # strip userinfo
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("["):             # IPv6 literal
        return netloc.split("]")[0] + "]"
    return _to_ascii_host(netloc.split(":")[0])


def extract_features(url: str) -> dict:
    """Return the nine model features for a single URL as a dict."""
    url = normalize_url(url)
    hostname = get_hostname(url)
    return {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": 1 if _IP_LIKE.search(url) else 0,
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_or": url.count("|"),
    }


def extract_vector(url: str) -> list:
    """Return the nine features as an ordered list (model input row)."""
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]


if __name__ == "__main__":
    import json
    import sys

    # The Windows console defaults to cp1252 and cannot print an
    # internationalised URL; keep the CLI usable for those too.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    for arg in sys.argv[1:] or ["http://secure-login.paypal.com.verify-account.tk/a1b2c3d4e5f6/?id=1&x=2"]:
        print(arg)
        print(json.dumps(extract_features(arg), indent=2))
