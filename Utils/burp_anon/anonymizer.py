"""Core pseudonymization engine.

Three layers, applied in order of specificity:
  1. Structured handlers (request line, headers, cookies, JSON/form/multipart
     bodies) that know *which* values are secrets by position or key name.
  2. Shape-aware mappers (hosts, URLs, emails, IPs, UUIDs, JWTs) that keep the
     value's shape so the traffic still "looks right" to a reader or an LLM.
  3. A generic text pass (secret formats, hex blobs, cards, SSNs, phones,
     client terms) over everything that is left.

All replacements go through `Mapping`, so a value maps to one placeholder.
"""

from __future__ import annotations

import base64
import json
import re
from collections import Counter
from typing import Any, Callable, Optional
from urllib.parse import quote_plus, unquote_plus, urlsplit, urlunsplit

from . import detectors as D
from .mapping import Mapping

RE_REQ_LINE = re.compile(r"^([A-Z]{3,12}) (\S+) (HTTP/\d(?:\.\d)?)\s*$")
RE_RES_LINE = re.compile(r"^(HTTP/\d(?:\.\d)?) (\d{3})(.*)$")
RE_JSON_KV = re.compile(r'"((?:[^"\\]|\\.){1,80})"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?)')
RE_XML_ELEM = re.compile(r"<([A-Za-z_][\w:.\-]*)((?:\s[^<>]*)?)>([^<]+)</\1\s*>")
RE_HTML_INPUT = re.compile(
    r"""(<input\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*\bvalue\s*=\s*["'])([^"']*)(["'])""", re.I
)
RE_HTML_INPUT_REV = re.compile(
    r"""(<input\b[^>]*\bvalue\s*=\s*["'])([^"']*)(["'][^>]*\bname\s*=\s*["']([^"']+)["'])""", re.I
)
RE_COOKIE_DOMAIN = re.compile(r"(?i)(;\s*domain=)(\.?)([^;\s]+)")

# A regex replacement callback: takes a match object, returns the replacement.
_Replacer = Callable[[re.Match], str]


def _norm_key(key):
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _label(key):
    lab = re.sub(r"[^A-Za-z0-9]+", "_", key).strip("_").upper()
    return lab[:24] or "FIELD"


class Anonymizer:
    def __init__(
        self, mapping: Optional[Mapping] = None, config: Optional[dict[str, Any]] = None
    ) -> None:
        from .config import DEFAULT_CONFIG

        self.cfg: dict[str, Any] = config if config is not None else DEFAULT_CONFIG
        self.mapping = mapping if mapping is not None else Mapping()
        self.stats: Counter[str] = Counter()
        c = self.cfg
        self.detect = c.get("detect", {})
        self.keep_hosts = {h.lower() for h in c.get("keep_hosts", [])}
        self.keep_base_hosts = {h.lower() for h in c.get("keep_base_hosts", [])}
        self.generic_labels = set(c.get("generic_labels", []))
        self.sensitive_headers = {h.lower() for h in c.get("sensitive_headers", [])}
        self.sensitive_header_subs = [s.lower() for s in c.get("sensitive_header_substrings", [])]
        self.nonsensitive_headers = {h.lower() for h in c.get("nonsensitive_headers", [])}
        self.key_subs = [_norm_key(k) for k in c.get("sensitive_key_substrings", [])]
        self.key_exact = {_norm_key(k) for k in c.get("sensitive_keys_exact", [])}
        self.key_nonsens = {_norm_key(k) for k in c.get("nonsensitive_keys", [])}
        self.keep_cookies = {k.lower() for k in c.get("keep_cookies", [])}
        self.keep_private_ips = bool(c.get("keep_private_ips", False))
        self.min_hex = int(c.get("min_hex_len", 32))
        self.re_hex = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{%d,}(?![0-9A-Za-z])" % self.min_hex)
        pats = D.DEFAULT_SECRET_PATTERNS + list(c.get("secret_patterns", []))
        self.secret_res = [re.compile(p) for p in pats]
        terms = sorted({t for t in c.get("terms", []) if t.strip()}, key=len, reverse=True)
        self.terms_re = None
        if terms:
            alt = "|".join(re.escape(t) for t in terms)
            self.terms_re = re.compile(r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])" % alt, re.I)

        # Ordered free-text detector pipeline: (detect-flag name, regex, replacer).
        # _text_no_url() applies each in turn when its flag is on. Order matters
        # (e.g. email before host so the domain is mapped as part of the email).
        # `terms` is handled separately in _text_no_url because it is gated on
        # self.terms_re being built at all.
        self._text_pipeline: list[tuple[str, re.Pattern, _Replacer]] = [
            ("email", D.RE_EMAIL, lambda m: self.email(m.group(0))),
            ("host", D.RE_HOST, lambda m: self.host(m.group(0), strict=True)),
            ("ipv4", D.RE_IPV4, lambda m: self.ipv4(m.group(0))),
            ("ipv6", D.RE_IPV6, lambda m: self.ipv6(m.group(0))),
            ("uuid", D.RE_UUID, lambda m: self.uuid(m.group(0))),
            ("hex", self.re_hex, lambda m: self._ph("hex", m.group(0), "HEX")),
            ("card", D.RE_CARD, self._card),
            ("ssn", D.RE_SSN, lambda m: self._ph("ssn", m.group(0), "SSN")),
            ("phone", D.RE_PHONE, lambda m: self._ph("phone", m.group(0), "PHONE")),
        ]

    # ------------------------------------------------------------------ utils
    def _ph(self, category, value, label):
        """Generic bracketed placeholder: [LABEL_n]."""
        out = self.mapping.get(category, value, lambda n: "[%s_%d]" % (label, n))
        if out != value:
            self.stats[label] += 1
        return out

    def _on(self, name):
        return self.detect.get(name, True)

    def is_sensitive_key(self, key):
        k = _norm_key(key)
        if not k or k in self.key_nonsens:
            return False
        if k in self.key_exact or k.endswith("key"):
            return True
        return any(s in k for s in self.key_subs)

    # ------------------------------------------------------------ shape maps
    def host(self, h: str, strict: bool = False) -> str:
        """Pseudonymize a hostname, keeping generic subdomains and the TLD shape.
        strict=True (free-text context) only maps names with a known TLD."""
        raw = h
        hl = h.lower().rstrip(".")
        if not hl or self.mapping.is_placeholder(hl) or hl.endswith(".example"):
            return raw
        if hl == "localhost" or hl in self.keep_hosts:
            return raw
        if any(hl.endswith("." + k) for k in self.keep_hosts):
            return raw
        labels = hl.split(".")
        if len(labels) == 1:
            if strict:
                return raw
            return self._host_base(hl)
        tld = labels[-1]
        if strict and tld not in D.KNOWN_TLDS:
            return raw
        if not re.fullmatch(r"[a-z]{2,24}", tld):
            return raw  # IPs and the like are handled elsewhere
        base_n = 2
        if len(labels) >= 3 and labels[-2] in D.SECOND_LEVEL and len(tld) == 2:
            base_n = 3
        base = ".".join(labels[-base_n:])
        subs = labels[:-base_n]
        if base in self.keep_base_hosts or any(
            base.endswith("." + k) for k in self.keep_base_hosts
        ):
            base_ph = base
        else:
            base_ph = self._host_base(base)
        out = []
        for lab in subs:
            if lab in self.generic_labels or re.fullmatch(r"(?:v\d+|\d+|[a-z]{1,2}\d{0,2})", lab):
                out.append(lab)
            else:
                ph = self.mapping.get("sub", lab, lambda n: "sub%d" % n)
                if ph != lab:
                    self.stats["SUB"] += 1
                out.append(ph)
        return ".".join(out + [base_ph])

    def _host_base(self, base):
        ph = self.mapping.get("host", base, lambda n: "target%d.example" % n)
        if ph != base:
            self.stats["HOST"] += 1
        return ph

    def email(self, e: str) -> str:
        if self.mapping.is_placeholder(e):
            return e
        local, _, dom = e.rpartition("@")
        dom_ph = self.host(dom)
        key = e.lower()
        ph = self.mapping.get("email", key, lambda n: "user%d@%s" % (n, dom_ph))
        if ph != key:
            self.stats["EMAIL"] += 1
        return ph

    def ipv4(self, ip: str) -> str:
        if self.mapping.is_placeholder(ip) or not D.valid_ipv4(ip):
            return ip
        # Value comparison for passthrough IPs, not a socket bind.
        if ip in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):  # nosec B104
            return ip
        if self.keep_private_ips and D.is_private_ip(ip):
            return ip
        if ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
            return ip  # documentation range: already a placeholder

        def make(n):
            blocks = ["192.0.2.%d", "198.51.100.%d", "203.0.113.%d"]
            i = n - 1
            if i >= 254 * len(blocks):
                return "[IP_%d]" % n
            return blocks[i // 254] % (i % 254 + 1)

        ph = self.mapping.get("ip", ip, make)
        if ph != ip:
            self.stats["IP"] += 1
        return ph

    def ipv6(self, ip: str) -> str:
        if self.mapping.is_placeholder(ip) or not D.valid_ipv6(ip):
            return ip
        low = ip.lower()
        if low in ("::", "::1") or low.startswith("2001:db8:"):
            return ip
        if self.keep_private_ips and D.is_private_ip(ip):
            return ip
        ph = self.mapping.get("ip6", low, lambda n: "2001:db8::%x" % n)
        if ph != low:
            self.stats["IP6"] += 1
        return ph

    def uuid(self, u: str) -> str:
        low = u.lower()
        if self.mapping.is_placeholder(low) or low.startswith("00000000-0000-4000-8000-"):
            return u
        ph = self.mapping.get("uuid", low, lambda n: "00000000-0000-4000-8000-%012d" % n)
        if ph != low:
            self.stats["UUID"] += 1
        return ph

    def jwt(self, tok: str) -> str:
        """Replace a JWT with a synthetic one: header kept (minus kid), claims
        anonymized with the normal rules, signature replaced."""
        if self.mapping.is_placeholder(tok):
            return tok

        def b64d(s):
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

        def b64e(obj):
            raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        def make(n):
            try:
                hdr = json.loads(b64d(tok.split(".")[0]))
                pay = json.loads(b64d(tok.split(".")[1]))
            except (ValueError, IndexError):
                # not decodable JSON/base64 (binascii.Error and JSONDecodeError
                # both subclass ValueError); fall back to an opaque placeholder.
                return "[JWT_%d]" % n
            if isinstance(hdr, dict) and "kid" in hdr:
                hdr["kid"] = self._ph("field:KID", str(hdr["kid"]), "KID")
            if isinstance(hdr, dict) and "jku" in hdr:
                hdr["jku"] = self.text(str(hdr["jku"]))
            pay = self._json(pay)
            return "%s.%s.REDACTED_SIGNATURE_%d" % (b64e(hdr), b64e(pay), n)

        ph = self.mapping.get("jwt", tok, make)
        if ph != tok:
            self.stats["JWT"] += 1
        return ph

    def url(self, u: str) -> str:
        if self.mapping.is_placeholder(u):
            return u
        trail = ""
        while u and u[-1] in ".,;:)]}'\"":
            trail = u[-1] + trail
            u = u[:-1]
        try:
            parts = urlsplit(u)
        except ValueError:
            return self._text_no_url(u) + trail
        netloc = parts.netloc
        userinfo, _, hostport = netloc.rpartition("@")
        host, _, port = (
            hostport.partition(":") if not hostport.startswith("[") else (hostport, "", "")
        )
        if hostport.startswith("["):
            host6 = hostport[1 : hostport.find("]")]
            host = "[" + self.ipv6(host6) + "]"
            rest = hostport[hostport.find("]") + 1 :]
            hostport = host + rest
        else:
            if D.RE_IPV4.fullmatch(host):
                host = self.ipv4(host)
            elif host:
                host = self.host(host)
            hostport = host + (":" + port if port else "")
        if userinfo:
            userinfo = self._ph("userinfo", userinfo, "USERINFO") + "@"
        path = self._text_no_url(parts.path) if parts.path else parts.path
        query = self.params(parts.query) if parts.query else parts.query
        frag = parts.fragment
        if frag:
            frag = self.params(frag) if "=" in frag else self._text_no_url(frag)
        return urlunsplit((parts.scheme, userinfo + hostport, path, query, frag)) + trail

    def params(self, qs: str) -> str:
        """key=value&key2=value2 (query strings, form bodies, fragments)."""
        out = []
        for pair in qs.split("&"):
            if "=" not in pair:
                out.append(self._reencode(pair, self.value(unquote_plus(pair))))
                continue
            k, v = pair.split("=", 1)
            kd, vd = unquote_plus(k), unquote_plus(v)
            nv = self.value(vd, kd)
            out.append(self.text(k) + "=" + self._reencode(v, nv))
        return "&".join(out)

    @staticmethod
    def _reencode(raw, new):
        decoded = unquote_plus(raw)
        if new == decoded:
            return raw
        if "%" in raw or "+" in raw:
            return quote_plus(new, safe="[]")
        return new

    # ------------------------------------------------------------ value pass
    def _shape(self, v):
        """Exact-shape mappers for a whole value; None if no shape matched."""
        s = v.strip()
        if D.RE_JWT.fullmatch(s):
            return self.jwt(s)
        if D.RE_EMAIL.fullmatch(s):
            return self.email(s)
        if D.RE_URL.fullmatch(s):
            return self.url(s)
        if D.RE_IPV4.fullmatch(s):
            return self.ipv4(s)
        if D.RE_UUID.fullmatch(s):
            return self.uuid(s)
        if D.valid_ipv6(s) and ":" in s:
            return self.ipv6(s)
        if D.RE_HOST.fullmatch(s):
            return self.host(s)
        return None

    def value(self, v: str, key: Optional[str] = None) -> str:
        """Anonymize a leaf value (JSON string, form field, cookie...)."""
        if not v or self.mapping.is_placeholder(v):
            return v
        if key is not None and self.is_sensitive_key(key):
            shaped = self._shape(v)
            if shaped is not None and shaped != v:
                return shaped
            lab = _label(key)
            return self._ph("field:" + lab, v, lab)
        out = self.text(v)
        if out != v:
            return out
        if self._on("blob") and D.looks_like_blob(v):
            return self._ph("blob", v, "BLOB")
        return v

    # ------------------------------------------------------------- text pass
    def text(self, s: str) -> str:
        """Generic detectors over free text."""
        if not s or self.mapping.is_placeholder(s):
            return s
        if self._on("secrets"):
            s = D.RE_PRIVKEY.sub(lambda m: self._ph("secret", m.group(0), "PRIVATE_KEY"), s)
            for rx in self.secret_res:
                s = rx.sub(lambda m: self._ph("secret", m.group(0), "SECRET"), s)
        if self._on("jwt"):
            s = D.RE_JWT.sub(lambda m: self.jwt(m.group(0)), s)
        if self._on("url"):
            s = D.RE_URL.sub(lambda m: self.url(m.group(0)), s)
        return self._text_no_url(s)

    def _text_no_url(self, s: str) -> str:
        if not s:
            return s
        for name, rx, fn in self._text_pipeline:
            if self._on(name):
                s = rx.sub(fn, s)
        if self._on("terms") and self.terms_re:
            s = self.terms_re.sub(lambda m: self._term(m.group(0)), s)
        return s

    def _card(self, m):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and D.luhn_ok(digits):
            return self._ph("card", m.group(0), "CARD")
        return m.group(0)

    def _term(self, word):
        ph = self.mapping.get("term", word.lower(), lambda n: "[CLIENT_%d]" % n)
        if ph != word.lower():
            self.stats["CLIENT"] += 1
        return ph

    # ----------------------------------------------------------- structured
    def _json(self, obj, parent_key=None):
        if isinstance(obj, dict):
            return {self.text(k): self._json(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._json(v, parent_key) for v in obj]
        if isinstance(obj, str):
            return self.value(obj, parent_key)
        if isinstance(obj, bool) or obj is None:
            return obj
        if isinstance(obj, (int, float)):
            if parent_key is not None and self.is_sensitive_key(parent_key):
                return self.value(str(obj), parent_key)
            return obj
        return obj

    def json_body(self, body):
        try:
            obj = json.loads(body)
        except (ValueError, RecursionError):
            return self._json_fallback(body)
        if isinstance(obj, (str, int, float)) or obj is None:
            return self.text(body)
        out = self._json(obj)
        pretty = "\n" in body.strip()
        if pretty:
            return json.dumps(out, indent=2, ensure_ascii=False)
        return json.dumps(out, separators=(",", ":"), ensure_ascii=False)

    def _json_fallback(self, body):
        def repl(m):
            key, val = m.group(1), m.group(2)
            if val.startswith('"'):
                inner = val[1:-1]
                try:
                    dec = json.loads(val)
                except ValueError:
                    dec = inner
                nv = self.value(dec, key)
                if nv == dec:
                    return m.group(0)
                return '"%s":%s' % (key, json.dumps(nv, ensure_ascii=False))
            if self.is_sensitive_key(key):
                return '"%s":"%s"' % (key, self.value(val, key))
            return m.group(0)

        return self.text(RE_JSON_KV.sub(repl, body))

    def form_body(self, body):
        return self.params(body.strip("\r\n")) + body[len(body.rstrip("\r\n")) :]

    def multipart_body(self, body, boundary):
        delim = "--" + boundary
        pieces = body.split(delim)
        if len(pieces) < 3:
            return self.text_body(body)
        for i in range(1, len(pieces) - 1):
            piece = pieces[i]
            if "\n\n" not in piece:
                pieces[i] = self.text(piece)
                continue
            head, content = piece.split("\n\n", 1)
            m = re.search(r'name="([^"]*)"', head, re.I)
            name = m.group(1) if m else None
            is_file = re.search(r'filename="', head, re.I)
            trailing = content[len(content.rstrip("\r\n")) :]
            core = content.rstrip("\r\n")
            if is_file:
                if D.is_binary(core):
                    new = "[binary file content omitted, %d bytes]" % len(
                        core.encode("utf-8", "replace")
                    )
                else:
                    new = self.text_body(core)
            else:
                new = self.value(core, name) if core else core
            pieces[i] = self.text(head) + "\n\n" + new + trailing
        return delim.join(pieces)

    def text_body(self, body):
        """Any text body: XML/HTML field rules, then the generic pass."""
        if D.is_binary(body):
            return "[binary body omitted, %d bytes]" % len(body.encode("utf-8", "replace"))

        def xml_repl(m):
            tag = m.group(1).split(":")[-1]
            if self.is_sensitive_key(tag):
                return "<%s%s>%s</%s>" % (
                    m.group(1),
                    m.group(2),
                    self.value(m.group(3).strip(), tag),
                    m.group(1),
                )
            return m.group(0)

        def input_repl(m):
            if self.is_sensitive_key(m.group(2)) and m.group(3):
                return m.group(1) + self.value(m.group(3), m.group(2)) + m.group(4)
            return m.group(0)

        def input_repl_rev(m):
            if self.is_sensitive_key(m.group(4)) and m.group(2):
                return m.group(1) + self.value(m.group(2), m.group(4)) + m.group(3)
            return m.group(0)

        body = RE_XML_ELEM.sub(xml_repl, body)
        body = RE_HTML_INPUT.sub(input_repl, body)
        body = RE_HTML_INPUT_REV.sub(input_repl_rev, body)
        if "{" in body:  # inline JSON (script blocks, JSONP, JSON in HTML)
            body = RE_JSON_KV.sub(lambda m: self._json_fallback(m.group(0)), body)
        return self.text(body)

    # --------------------------------------------------------------- headers
    def cookie_header(self, value):
        out = []
        for part in value.split(";"):
            if "=" not in part:
                out.append(self.text(part))
                continue
            name, val = part.split("=", 1)
            lead = name[: len(name) - len(name.lstrip())]
            n = name.strip()
            v = val.strip()
            if n.lower() in self.keep_cookies or not v:
                out.append(lead + n + "=" + val)
            else:
                out.append(lead + self.text(n) + "=" + self._cookie_value(v))
        return ";".join(out)

    def _cookie_value(self, v):
        shaped = self._shape(v)
        if shaped is not None and shaped != v:
            return shaped
        return self._ph("cookie", v, "COOKIE")

    def set_cookie_header(self, value):
        first, sep, rest = value.partition(";")
        if "=" in first:
            name, val = first.split("=", 1)
            if name.strip().lower() in self.keep_cookies or not val.strip():
                first = name + "=" + val
            else:
                first = self.text(name) + "=" + self._cookie_value(val.strip())
        rest = RE_COOKIE_DOMAIN.sub(
            lambda m: m.group(1) + m.group(2) + self.host(m.group(3)), rest
        )
        return first + sep + self.text(rest)

    def auth_header(self, value):
        scheme, sep, cred = value.strip().partition(" ")
        if not sep:
            return self._ph("token", value.strip(), "TOKEN")
        cred = cred.strip()
        if D.RE_JWT.fullmatch(cred):
            return scheme + " " + self.jwt(cred)
        if scheme.lower() == "basic":
            return scheme + " " + self._ph("basic", cred, "BASIC")
        return scheme + " " + self._ph("token", cred, "TOKEN")

    def header(self, name, value):
        n = name.strip().lower()
        v = value.strip()
        lead = value[: len(value) - len(value.lstrip())]
        if not v:
            return value
        if n in ("authorization", "proxy-authorization"):
            return lead + self.auth_header(v)
        if n == "cookie":
            return lead + self.cookie_header(v)
        if n == "set-cookie":
            return lead + self.set_cookie_header(v)
        if n == "host":
            host, _, port = v.rpartition(":") if re.search(r":\d+$", v) else (v, "", "")
            if D.RE_IPV4.fullmatch(host):
                host = self.ipv4(host)
            else:
                host = self.host(host)
            return lead + host + (":" + port if port else "")
        if n in self.sensitive_headers or (
            n not in self.nonsensitive_headers and any(s in n for s in self.sensitive_header_subs)
        ):
            shaped = self._shape(v)
            if shaped is not None and shaped != v:
                return lead + shaped
            return lead + self._ph("header:" + n, v, _label(n))
        return lead + self.text(v)

    # -------------------------------------------------------------- messages
    def anonymize(self, text: str) -> str:
        """Anonymize raw HTTP text (one or more requests/responses, or plain text)."""
        crlf = "\r\n" in text
        norm = text.replace("\r\n", "\n")
        lines = norm.split("\n")
        msgs: list[dict[str, Any]] = []
        pre: list[str] = []
        cur: Optional[dict[str, Any]] = None
        state: Optional[str] = None
        prev_blank = True
        for line in lines:
            is_start = bool(RE_REQ_LINE.match(line) or RE_RES_LINE.match(line))
            if is_start and (cur is None or state == "headers" or prev_blank):
                cur = {"start": line, "headers": [], "body": []}
                msgs.append(cur)
                state = "headers"
                prev_blank = False
                continue
            if cur is None:
                pre.append(line)
            elif state == "headers":
                if line.strip() == "":
                    state = "body"
                else:
                    cur["headers"].append(line)
            else:
                cur["body"].append(line)
            prev_blank = line.strip() == ""
        if not msgs:
            out = self.plain(norm)
        else:
            chunks: list[str] = []
            if pre:
                chunks.append(self.plain("\n".join(pre)))
            for m in msgs:
                chunks.append(self._message(m))
            out = "\n".join(chunks)
        return out.replace("\n", "\r\n") if crlf else out

    def plain(self, text):
        stripped = text.strip()
        if stripped[:1] in "{[" and stripped[-1:] in "}]":
            try:
                json.loads(stripped)
                lead = text[: len(text) - len(text.lstrip())]
                trail = text[len(text.rstrip()) :]
                return lead + self.json_body(stripped) + trail
            except ValueError:
                pass
        return self.text_body(text)

    def _message(self, m):
        start = m["start"]
        rm = RE_REQ_LINE.match(start)
        if rm:
            method, target, ver = rm.groups()
            if "://" in target:
                target = self.url(target)
            else:
                path, sep, qs = target.partition("?")
                target = self._text_no_url(path) + sep + (self.params(qs) if qs else "")
            start = "%s %s %s" % (method, target, ver)
        else:
            start = self.text(start)

        headers, hdr_map = [], {}
        for h in m["headers"]:
            if ":" not in h or h[0] in " \t":
                headers.append(self.text(h))
                continue
            name, value = h.split(":", 1)
            hdr_map[name.strip().lower()] = value.strip()
            headers.append(name + ":" + self.header(name, value))

        body = "\n".join(m["body"])
        new_body = body
        if body.strip():
            core = body.rstrip("\r\n")
            trailing = body[len(core) :]
            new_core = self._body(core, hdr_map)
            new_body = new_core + trailing
            if new_core != core and self.cfg.get("update_content_length", True):
                headers = self._fix_content_length(headers, new_core)

        out = [start] + headers
        out.append("")  # blank line terminating the header block (always present)
        if m["body"]:
            out.append(new_body)
        return "\n".join(out)

    def _body(self, body, hdr_map):
        ctype = hdr_map.get("content-type", "").lower()
        stripped = body.strip()
        if "json" in ctype or (not ctype and stripped[:1] in "{[" and stripped[-1:] in "}]"):
            return self.json_body(body)
        if "x-www-form-urlencoded" in ctype:
            return self.form_body(body)
        if "multipart/" in ctype:
            bm = re.search(r'boundary="?([^";,\s]+)"?', ctype)
            if bm:
                return self.multipart_body(body, bm.group(1))
        if (
            not ctype
            and "\n" not in stripped
            and re.fullmatch(r"[^=&\s]+=[^&\s]*(?:&[^=&\s]+=[^&\s]*)*", stripped)
        ):
            return self.form_body(body)
        if "json" not in ctype and stripped[:1] in "{[" and stripped[-1:] in "}]":
            try:
                json.loads(stripped)
                return self.json_body(body)
            except ValueError:
                pass
        return self.text_body(body)

    @staticmethod
    def _fix_content_length(headers, body):
        n = len(body.encode("utf-8", "replace"))
        out = []
        for h in headers:
            if h.lower().startswith("content-length:"):
                out.append("Content-Length: %d" % n)
            else:
                out.append(h)
        return out

    # ---------------------------------------------------------------- report
    def summary(self) -> str:
        if not self.stats:
            return "nothing replaced"
        return ", ".join("%s x%d" % (k, v) for k, v in sorted(self.stats.items()))
