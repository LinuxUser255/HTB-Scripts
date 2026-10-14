"""Default detection rules and user config loading.

User overrides live in ~/.config/burp-anon/config.json (or --config PATH).
List-valued keys are *merged* with the defaults unless the key is prefixed
with "!" in the user file (e.g. "!keep_hosts": [...] replaces the list).
"""
import json
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("~/.config/burp-anon/config.json").expanduser()
DEFAULT_MAP_DIR = Path("~/.burp-anon/sessions").expanduser()

DEFAULT_CONFIG = {
    # Client-identifying words (company name, product codename...). Case-insensitive.
    "terms": [],

    # Hosts kept verbatim (base domain and every subdomain).
    "keep_hosts": [
        "localhost", "example.com", "example.org", "example.net",
        "w3.org", "schema.org", "xmlsoap.org", "openxmlformats.org", "purl.org", "ietf.org",
        "mozilla.org", "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
        "google-analytics.com", "doubleclick.net", "cloudflare.com", "cloudflareinsights.com",
        "jquery.com", "jsdelivr.net", "unpkg.com", "bootstrapcdn.com", "fontawesome.com",
        "github.com", "githubusercontent.com", "microsoft.com", "apple.com", "facebook.com",
        "twitter.com", "x.com", "youtube.com", "linkedin.com", "wikipedia.org", "gmail.com",
        "portswigger.net", "burpcollaborator.net", "oastify.com", "interact.sh", "ngrok.io",
    ],
    # Hosts whose base domain is kept but whose non-generic subdomains are still
    # pseudonymized (bucket names, tenant names...): acme-prod.s3.amazonaws.com -> sub1.s3.amazonaws.com
    "keep_base_hosts": [
        "amazonaws.com", "cloudfront.net", "azurewebsites.net", "windows.net", "azure.com",
        "azureedge.net", "herokuapp.com", "github.io", "okta.com", "auth0.com", "salesforce.com",
        "force.com", "sharepoint.com", "onmicrosoft.com", "cloudapp.net", "appspot.com",
        "firebaseio.com", "akamaized.net", "akamaihd.net", "fastly.net", "netlify.app", "vercel.app",
    ],
    # Subdomain labels that carry no client identity and are kept.
    "generic_labels": [
        "www", "api", "apis", "app", "apps", "auth", "login", "sso", "idp", "oauth", "id", "accounts",
        "account", "static", "cdn", "assets", "img", "images", "media", "mail", "smtp", "imap", "admin",
        "dev", "develop", "staging", "stage", "stg", "prod", "production", "test", "testing", "uat", "qa",
        "m", "mobile", "portal", "my", "secure", "shop", "store", "blog", "docs", "help", "support",
        "status", "internal", "intranet", "vpn", "git", "gitlab", "jenkins", "ci", "ws", "wss", "graphql",
        "beta", "demo", "sandbox", "preview", "gateway", "gw", "proxy", "edge", "web", "web1", "web2",
        "s3", "storage", "files", "upload", "uploads", "download", "downloads", "fonts", "ajax", "code",
        "maps", "graph", "login-us", "ns1", "ns2", "mx", "mx1", "mx2", "ftp", "sftp", "autodiscover",
        "owa", "mail1", "mail2", "exchange", "remote", "citrix", "rdp", "dc", "dc1", "dc2", "ad", "ldap",
    ],
    # Keep RFC1918 / loopback etc. untouched (useful for HTB; off for client work).
    "keep_private_ips": False,

    # Header names whose entire value is replaced.
    "sensitive_headers": [
        "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "x-refresh-token",
        "x-csrf-token", "x-xsrf-token", "x-csrftoken", "csrf-token", "x-session-id", "x-session-token",
        "x-amz-security-token", "x-amz-credential", "x-amz-signature", "x-client-secret", "x-signature",
        "x-hub-signature", "x-hub-signature-256", "x-slack-signature", "x-shopify-access-token",
        "x-auth", "x-auth-key", "x-api-token", "x-token", "x-user-token", "x-identity-token",
        "x-ms-authorization", "x-goog-api-key", "x-pingother", "x-aspnet-version", "ocp-apim-subscription-key",
    ],
    # Substrings that mark a header as sensitive (whole value replaced).
    "sensitive_header_substrings": [
        "token", "secret", "apikey", "api-key", "csrf", "xsrf", "session", "signature", "credential",
        "password", "passwd",
    ],
    # Headers excluded from the substring rule (only generic detectors run on them).
    "nonsensitive_headers": ["www-authenticate", "content-security-policy", "content-security-policy-report-only"],

    # JSON / form / query / cookie / XML keys whose value is replaced (substring match on
    # the normalised key: lowercase, non-alphanumerics removed).
    "sensitive_key_substrings": [
        "password", "passwd", "passphrase", "secret", "token", "apikey", "accesskey", "privatekey",
        "clientsecret", "credential", "auth", "session", "csrf", "xsrf", "ssn", "socialsecurity",
        "creditcard", "cardnumber", "ccnumber", "cvv", "cvc", "iban", "swift", "bic", "accountnumber",
        "routing", "sortcode", "dob", "dateofbirth", "birthdate", "birthday", "phone", "mobile", "email",
        "firstname", "lastname", "fullname", "givenname", "familyname", "surname", "displayname",
        "username", "userid", "address", "street", "zipcode", "postcode", "postal", "latitude",
        "longitude", "otp", "signature", "hmac", "nonce", "salt", "passport", "nationalid", "taxid",
        "licensenumber", "driverslicense", "securityanswer", "companyname", "organization",
        "organisation", "orgname", "employer", "bearer", "refresh", "idtoken", "mfa", "totp", "recovery",
        "cookie", "ipaddress", "clientip", "remoteaddr", "hostname",
    ],
    # Exact-match (normalised) sensitive keys.
    "sensitive_keys_exact": [
        "name", "user", "login", "pin", "sub", "jti", "sid", "upn", "oid", "tid", "key", "pwd", "pass",
        "pw", "code", "state", "hash", "sig", "account", "acct", "acctid", "accountid", "customerid",
        "company", "org", "tenant", "domain", "host", "ip", "lat", "lng", "lon", "zip", "tel", "cell",
        "fax", "ein", "vat", "card", "pan", "exp", "expiry", "ccexp", "answer", "question", "mothersmaidenname",
        "fname", "lname", "mname", "middlename", "nickname", "handle", "alias", "owner", "author",
        "creator", "contact", "recipient", "sender", "from", "to", "cc", "bcc", "realm", "uid", "guid", "uuid",
    ],
    # Keys explicitly NOT sensitive even if they match above (normalised form).
    "nonsensitive_keys": [
        "contenttype", "tokentype", "authtype", "sessiontimeout", "emailverified", "phoneverified",
        "exp", "iat", "nbf", "statecode", "statename", "hashalgorithm", "keytype", "codepage", "statuscode",
        "errorcode", "countrycode", "currencycode", "languagecode", "zipformat", "fromdate", "todate",
        "ccy", "owner_type", "ownertype", "authmethod", "authenticated", "authorized",
    ],
    # Cookie names whose value is kept.
    "keep_cookies": [],
    # Extra secret regexes (Python syntax) merged with the built-in list.
    "secret_patterns": [],
    # Set to false to disable individual generic detectors.
    "detect": {
        "jwt": True, "url": True, "email": True, "host": True, "ipv4": True, "ipv6": True,
        "uuid": True, "hex": True, "card": True, "ssn": True, "phone": True, "blob": True,
        "secrets": True, "terms": True,
    },
    "min_hex_len": 32,
    "update_content_length": True,
}


def _merge(base, user):
    out = dict(base)
    for k, v in user.items():
        replace = k.startswith("!")
        key = k.lstrip("!")
        if key not in out:
            out[key] = v
        elif isinstance(out[key], list) and isinstance(v, list) and not replace:
            out[key] = list(dict.fromkeys(out[key] + v))
        elif isinstance(out[key], dict) and isinstance(v, dict) and not replace:
            out[key] = {**out[key], **v}
        else:
            out[key] = v
    return out


def load_config(path=None):
    """Load defaults merged with the user's config file, if any."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    p = Path(path).expanduser() if path else DEFAULT_CONFIG_PATH
    if p.exists():
        try:
            user = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise SystemExit(f"config {p}: invalid JSON: {e}")
        cfg = _merge(cfg, user)
    elif path:
        raise SystemExit(f"config not found: {p}")
    return cfg


def write_default_config(path=None):
    p = Path(path).expanduser() if path else DEFAULT_CONFIG_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    skeleton = {
        "terms": ["AcmeCorp", "acme"],
        "keep_hosts": [],
        "keep_base_hosts": [],
        "keep_private_ips": False,
        "sensitive_key_substrings": [],
        "nonsensitive_keys": [],
        "keep_cookies": [],
        "secret_patterns": [],
        "detect": {},
    }
    p.write_text(json.dumps(skeleton, indent=2) + "\n", encoding="utf-8")
    return p
