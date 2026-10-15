import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from burp_anon import Anonymizer, Mapping, load_config  # noqa: E402
from burp_anon.config import DEFAULT_CONFIG  # noqa: E402


def b64url(obj):
    return (
        base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )


def jwt(payload, header=None):
    return "%s.%s.c2lnbmF0dXJl" % (
        b64url(header or {"alg": "HS256", "typ": "JWT"}),
        b64url(payload),
    )


def make(terms=(), **cfg_over):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["terms"] = list(terms)
    cfg.update(cfg_over)
    return Anonymizer(Mapping(), cfg)


REQ = (
    "POST /api/login?next=https%3A%2F%2Fportal.acme.com%2Fx&q=1 HTTP/1.1\r\n"
    "Host: api.acme.com\r\n"
    "Cookie: sid=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08; lang=en\r\n"
    "Authorization: Bearer "
    + jwt(
        {"sub": "jdoe@acme.com", "name": "John Doe", "role": "admin"},
        {"alg": "RS256", "kid": "k1"},
    )
    + "\r\n"
    "X-Api-Key: sk_live_4eC39HqLyjWDarjtT1zdp7dc\r\n"
    "X-Forwarded-For: 203.45.67.89\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 1\r\n"
    "\r\n"
    '{"username":"jdoe","password":"Winter2024!","email":"john.doe@acme.com","card":"4111 1111 1111 1111",'
    '"ssn":"123-45-6789","id":"c3b2a1d0-1234-4abc-9def-0123456789ab","profile":{"first_name":"John"},"ok":true,"n":3}\r\n'
)
RES = (
    "HTTP/1.1 200 OK\r\n"
    "Set-Cookie: sid=abcdef1234567890abcdef1234567890abcdef12; Path=/; Domain=.acme.com; HttpOnly\r\n"
    "Server: nginx/1.25\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    '{"user":{"email":"john.doe@acme.com","name":"John Doe"},"ip":"10.1.2.3","aws":"AKIAIOSFODNN7EXAMPLE",'
    '"s3":"https://acme-prod.s3.amazonaws.com/x","cdn":"https://cdnjs.cloudflare.com/ajax/libs/jquery.min.js"}\r\n'
)


class StructuredTests(unittest.TestCase):
    def setUp(self):
        self.a = make(terms=["acme"])
        self.out = self.a.anonymize(REQ + "\r\n" + RES)

    def test_no_leaks(self):
        for secret in (
            "acme.com",
            "9f86d081",
            "Winter2024",
            "john.doe",
            "John Doe",
            "jdoe",
            "4111",
            "123-45-6789",
            "sk_live",
            "203.45.67.89",
            "10.1.2.3",
            "AKIA",
            "abcdef1234567890",
            "c3b2a1d0",
            "acme-prod",
            'k1"',
        ):
            self.assertNotIn(secret, self.out, secret)
        # the JWT payload must not leak either (decode it back)
        tok = [l for l in self.out.splitlines() if l.startswith("Authorization")][0].split()[-1]
        pay = base64.urlsafe_b64decode(tok.split(".")[1] + "==").decode()
        self.assertNotIn("acme", pay)
        self.assertNotIn("John", pay)
        self.assertIn('"role":"admin"', pay)  # non-sensitive claims survive

    def test_shapes_preserved(self):
        self.assertIn("Host: api.target1.example", self.out)
        self.assertIn("next=https%3A%2F%2Fportal.target1.example%2Fx&q=1", self.out)
        self.assertIn("Domain=.target1.example", self.out)
        self.assertIn("X-Forwarded-For: 192.0.2.1", self.out)
        self.assertIn("00000000-0000-4000-8000-000000000001", self.out)
        self.assertIn("lang=[COOKIE_2]", self.out)
        self.assertIn('"password":"[PASSWORD_1]"', self.out)
        self.assertIn('"ok":true,"n":3', self.out)
        self.assertIn("https://cdnjs.cloudflare.com/ajax/libs/jquery.min.js", self.out)
        self.assertIn("https://sub1.s3.amazonaws.com/x", self.out)
        self.assertIn("Server: nginx/1.25", self.out)
        self.assertIn("\r\n", self.out)

    def test_consistency(self):
        # jdoe@acme.com (JWT sub) is user1; john.doe@acme.com appears in both bodies as user2
        self.assertEqual(self.out.count("user2@target1.example"), 2)
        self.assertEqual(self.a.host("evil.acme.com"), "sub2.target1.example")  # sub1 is acme-prod

    def test_content_length_updated(self):
        self.assertNotIn("Content-Length: 1\r\n", self.out)
        body = self.out.split("\r\n\r\n")[1]
        self.assertIn("Content-Length: %d" % len(body.rstrip("\r\n").encode()), self.out)

    def test_restore_roundtrip(self):
        restored = self.a.mapping.restore(self.out)
        import re

        norm = lambda s: re.sub(r"Content-Length: \d+", "CL", s)
        self.assertEqual(norm(restored), norm(REQ + "\r\n" + RES))

    def test_idempotent(self):
        self.assertEqual(self.a.anonymize(self.out), self.out)


class DetectorTests(unittest.TestCase):
    def test_form_body(self):
        a = make()
        out = a.anonymize(
            "POST /x HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n"
            "user=bob%40corp.io&pass=hunter2&csrf=ZmFrZQ&page=2\n"
        )
        self.assertIn("user=user1%40target1.example", out)
        self.assertIn("pass=[PASS_1]", out)
        self.assertIn("csrf=[CSRF_1]", out)
        self.assertIn("page=2", out)

    def test_multipart(self):
        a = make()
        body = (
            '------b\nContent-Disposition: form-data; name="password"\n\nsecret1\n'
            '------b\nContent-Disposition: form-data; name="file"; filename="a.txt"\nContent-Type: text/plain\n\n'
            "hello admin@corp.io\n------b--\n"
        )
        out = a.anonymize(
            "POST /u HTTP/1.1\nContent-Type: multipart/form-data; boundary=----b\n\n" + body
        )
        self.assertIn("[PASSWORD_1]", out)
        self.assertNotIn("secret1", out)
        self.assertIn("hello user1@target1.example", out)

    def test_xml_and_html(self):
        a = make()
        out = a.text_body(
            "<user><password>pw1</password><role>x</role></user>"
            '<input type="hidden" name="csrf_token" value="abc123"><input name="q" value="shoes">'
        )
        self.assertIn("<password>[PASSWORD_1]</password>", out)
        self.assertIn("<role>x</role>", out)
        self.assertIn('value="[CSRF_TOKEN_1]"', out)
        self.assertIn('value="shoes"', out)

    def test_keep_and_private(self):
        a = make(keep_private_ips=True)
        out = a.text("10.10.11.5 and 8.8.4.4 and example.com and localhost")
        self.assertIn("10.10.11.5", out)
        self.assertNotIn("8.8.4.4", out)
        self.assertIn("example.com", out)
        self.assertIn("localhost", out)

    def test_hosts_in_text_need_known_tld(self):
        a = make()
        out = a.text("see jquery.min.js and README.md and setup.py and corp.internal and foo.bar")
        self.assertIn("jquery.min.js", out)
        self.assertIn("README.md", out)
        self.assertIn("setup.py", out)
        self.assertIn("foo.bar", out)
        self.assertNotIn("corp.internal", out)

    def test_terms_and_phone_and_basic(self):
        a = make(terms=["Globex Corp", "globex"])
        out = a.anonymize(
            "GET / HTTP/1.1\nHost: intranet\nAuthorization: Basic dXNlcjpwYXNz\n\n"
            "Welcome to Globex Corp (GLOBEX). Call +1 555-123-4567."
        )
        self.assertIn("[CLIENT_1]", out)
        self.assertIn("[CLIENT_2]", out)
        self.assertNotIn("lobex", out)
        self.assertIn("[PHONE_1]", out)
        self.assertIn("Authorization: Basic [BASIC_1]", out)
        self.assertIn("Host: target1.example", out)

    def test_private_key_and_hex(self):
        a = make()
        out = a.text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY----- h=" + "a" * 40
        )
        self.assertIn("[PRIVATE_KEY_1]", out)
        self.assertIn("h=[HEX_1]", out)

    def test_plain_json_and_blob(self):
        a = make()
        out = a.anonymize(
            '{"state": "a9F3kLm2Qx8ZpR7tWv1BnY4c", "path": "/api/v1/users/profile", "role": "user"}'
        )
        self.assertIn('"state":"[STATE_1]"', out)
        self.assertIn('"path":"/api/v1/users/profile"', out)
        self.assertEqual(a.value("a9F3kLm2Qx8ZpR7tWv1BnY4c"), "[BLOB_1]")
        self.assertEqual(a.value("/api/v1/users/profile"), "/api/v1/users/profile")

    def test_ipv6_and_url_userinfo(self):
        a = make()
        out = a.text(
            "http://admin:pw@[2001:4860:4860::8888]:8080/x and 2001:4860:4860::8888 and 12:30:45"
        )
        self.assertIn("http://[USERINFO_1]@[2001:db8::1]:8080/x", out)
        self.assertIn("12:30:45", out)
        self.assertNotIn("4860", out)


class MappingTests(unittest.TestCase):
    def test_persist_and_reload(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.json")
            m = Mapping(p)
            a = Anonymizer(m, DEFAULT_CONFIG)
            first = a.anonymize("GET / HTTP/1.1\nHost: one.corp.io\n\n")
            m.save()
            self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600")
            m2 = Mapping(p)
            a2 = Anonymizer(m2, DEFAULT_CONFIG)
            again = a2.anonymize("GET / HTTP/1.1\nHost: one.corp.io\n\n")
            self.assertEqual(first, again)
            self.assertIn(
                "Host: sub2.target1.example", a2.anonymize("GET / HTTP/1.1\nHost: two.corp.io\n\n")
            )
            self.assertIn("one.corp.io", m2.restore(first))

    def test_restore_boundaries(self):
        m = Mapping()
        m.get("host", "x.com", lambda n: "target%d.example" % n)
        for i in range(10):
            m.get("sub", "s%d" % i, lambda n: "sub%d" % n)
        self.assertEqual(m.restore("sub1 sub10 sub1x target1.example"), "s0 s9 sub1x x.com")

    def test_config_merge(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w") as f:
                json.dump(
                    {"terms": ["foo"], "!keep_hosts": ["only.me"], "detect": {"phone": False}}, f
                )
            cfg = load_config(p)
            self.assertEqual(cfg["terms"], ["foo"])
            self.assertEqual(cfg["keep_hosts"], ["only.me"])
            self.assertFalse(cfg["detect"]["phone"])
            self.assertTrue(cfg["detect"]["email"])


class TextPipelineTests(unittest.TestCase):
    """Exercises the data-driven _text_no_url() detector pipeline."""

    BLOB = (
        "mail jdoe@acme.com host api.acme.com ip 203.45.67.89 "
        "ip6 2001:4860:4860::8888 uuid c3b2a1d0-1234-4abc-9def-0123456789ab "
        "hex " + "a" * 40 + " card 4111 1111 1111 1111 ssn 123-45-6789 "
        "phone +1 555-123-4567 client Globex"
    )

    def test_pipeline_order(self):
        # The table order is load-bearing (e.g. email before host); lock it.
        a = make()
        names = [name for name, _, _ in a._text_pipeline]
        self.assertEqual(
            names,
            ["email", "host", "ipv4", "ipv6", "uuid", "hex", "card", "ssn", "phone"],
        )

    def test_all_detectors_fire(self):
        a = make(terms=["Globex"])
        out = a.text(self.BLOB)
        for secret in (
            "jdoe",
            "acme.com",
            "203.45.67.89",
            "4860",
            "c3b2a1d0",
            "a" * 40,
            "4111",
            "123-45-6789",
            "555-123-4567",
            "Globex",
        ):
            self.assertNotIn(secret, out, secret)
        for placeholder in (
            "user1@target1.example",
            "192.0.2.1",
            "2001:db8::1",
            "00000000-0000-4000-8000-000000000001",
            "[HEX_1]",
            "[CARD_1]",
            "[SSN_1]",
            "[PHONE_1]",
            "[CLIENT_1]",
        ):
            self.assertIn(placeholder, out, placeholder)

    def test_disabled_detector_is_skipped(self):
        # Turning a flag off must skip just that step; the rest still run.
        a = make(detect={"ipv4": False, "card": False})
        out = a.text("ip 203.45.67.89 card 4111 1111 1111 1111 mail x@acme.com")
        self.assertIn("203.45.67.89", out)  # ipv4 off -> untouched
        self.assertIn("4111 1111 1111 1111", out)  # card off -> untouched
        self.assertIn("user1@target1.example", out)  # email still on

    def test_terms_gate_without_terms(self):
        # terms defaults on, but with none configured terms_re is None: no-op, no crash.
        a = make()
        self.assertIsNone(a.terms_re)
        self.assertEqual(a.text("Globex only"), "Globex only")

    def test_pipeline_matches_explicit_if_chain(self):
        # Equivalence guard: the refactored loop must produce exactly what the
        # old explicit if-chain produced. `a` runs the loop; `b` runs the chain
        # by hand on a fresh instance (same input + order => identical numbering).
        import burp_anon.detectors as D

        a = make(terms=["Globex"])
        b = make(terms=["Globex"])
        looped = a._text_no_url(self.BLOB)

        s = self.BLOB
        if b._on("email"):
            s = D.RE_EMAIL.sub(lambda m: b.email(m.group(0)), s)
        if b._on("host"):
            s = D.RE_HOST.sub(lambda m: b.host(m.group(0), strict=True), s)
        if b._on("ipv4"):
            s = D.RE_IPV4.sub(lambda m: b.ipv4(m.group(0)), s)
        if b._on("ipv6"):
            s = D.RE_IPV6.sub(lambda m: b.ipv6(m.group(0)), s)
        if b._on("uuid"):
            s = D.RE_UUID.sub(lambda m: b.uuid(m.group(0)), s)
        if b._on("hex"):
            s = b.re_hex.sub(lambda m: b._ph("hex", m.group(0), "HEX"), s)
        if b._on("card"):
            s = D.RE_CARD.sub(b._card, s)
        if b._on("ssn"):
            s = D.RE_SSN.sub(lambda m: b._ph("ssn", m.group(0), "SSN"), s)
        if b._on("phone"):
            s = D.RE_PHONE.sub(lambda m: b._ph("phone", m.group(0), "PHONE"), s)
        if b._on("terms") and b.terms_re:
            s = b.terms_re.sub(lambda m: b._term(m.group(0)), s)

        self.assertEqual(looped, s)


if __name__ == "__main__":
    unittest.main()
