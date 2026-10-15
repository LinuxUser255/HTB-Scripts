# burp-anon

Pseudonymize Burp Suite requests and responses so you can paste them into an
LLM (or a report, or a ticket) without leaking client data. Pure Python 3.8+,
no third-party dependencies.

**Consistent**: the same host, token, email or ID always becomes the same
placeholder within a session, so the model can still reason about the traffic
(`user1@target1.example` logs in, gets `[COOKIE_3]`, then `[COOKIE_3]` is
replayed against `api.target1.example`).

**Reversible**: every replacement is stored in a mode-0600 map file. Paste the
LLM's answer back through `burp-anon restore` and the original hosts, cookies
and tokens are put back, ready for Repeater.

## Install

The launcher is `Utils/burp-anon` (the directory *above* this one). Pick one:

```bash
# Option A: no install. Run the package from the Utils/ directory.
cd /path/to/HTB-Scripts/Utils
python3 -m burp_anon --version

# Option B: put it on your PATH. Note the launcher lives in Utils/, not here.
ln -s "/path/to/HTB-Scripts/Utils/burp-anon" /usr/local/bin/burp-anon
burp-anon --version
```

The rest of this README writes `burp-anon`; if you didn't symlink it, read that
as `python3 -m burp_anon` run from `Utils/`.

## The Repeater loop (the normal workflow)

You do **not** paste request/response text as a command-line argument — bare
arguments are read as *filenames*. Instead, get the traffic in through the
clipboard or a pipe:

```bash
# 1. In Burp Repeater, select the request (or response), right-click -> Copy.
# 2. Anonymize the clipboard in place:
burp-anon -c -s clientA
# 3. Paste into the LLM. Work with its answer.
# 4. Copy the LLM's reply, then turn the placeholders back into real values:
burp-anon restore -c -s clientA
# 5. Paste the restored text back into Repeater and send.
```

`-s clientA` names the session. **`restore` must use the same `-s` as the
`anon` run that created the mapping** — otherwise the placeholders are unknown
and `restore` prints `mapping is empty` and changes nothing.

Prefer hands-free? Start `watch` once and every Burp "Copy" is anonymized on
the clipboard automatically (no `-c` needed per call):

```bash
burp-anon watch -s clientA -t "Acme Corp" -t acme
# ...now just Copy in Burp and paste into the LLM; restore with:
burp-anon restore -c -s clientA
```

## The four ways to feed it input

`anon` (and `restore`) read from exactly one source, in this priority:

| How | Example | When |
| --- | --- | --- |
| Clipboard (`-c`) | `burp-anon -c` | the Repeater loop above |
| File path(s) | `burp-anon req.txt res.txt -o anon.txt` | you saved the traffic to a file |
| Pipe / stdin | `pbpaste \| burp-anon -t acme \| tee anon.txt` | chaining with other tools |
| Interactive stdin | `burp-anon` then paste, Ctrl-D | quick one-off paste in the terminal |

```bash
# Burp "Save items" XML export (Proxy history, Sitemap, Repeater tabs)
burp-anon xml history.xml -o history.txt --xml-out history.anon.xml
```

## Sessions

Add `-s NAME` on every call for one engagement so placeholders stay consistent
across days (the same host always maps to the same `target1.example`):
`~/.burp-anon/sessions/NAME.json`. Default session is `default`. The mapping is
also what makes `restore` possible, so anon and restore must share a session.
`burp-anon map -s NAME` summarizes it; `--show` prints the secrets; `--clear`
deletes it when the engagement is over.

## What gets replaced

| Source | Placeholder |
| --- | --- |
| Hostnames (Host, Origin, Referer, URLs, JSON, text) | `api.target1.example` (generic subdomains like `api`, `www`, `auth` kept; others -> `sub1`) |
| Public and private IPv4 / IPv6 | `192.0.2.1`, `2001:db8::1` (documentation ranges) |
| Emails | `user1@target1.example` |
| `Authorization` header | `Bearer [TOKEN_1]`, `Basic [BASIC_1]` |
| JWTs anywhere | synthetic JWT: header kept, claims anonymized with the same rules, signature replaced |
| `Cookie` / `Set-Cookie` values | `[COOKIE_1]` (names kept, attributes kept) |
| Sensitive headers (`X-Api-Key`, `*-Token`, `*-Secret`, `*Session*`, `*Signature*` ...) | `[X_API_KEY_1]` |
| JSON / form / query / cookie / XML / `<input>` fields with sensitive names (`password`, `email`, `first_name`, `ssn`, `card`, `account`, `company`, `name`, `sub`, `state`, `code` ...) | `[PASSWORD_1]`, `[FIRST_NAME_1]` ... |
| Known secret formats (AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Twilio, SendGrid, Vault, private key blocks ...) | `[SECRET_1]`, `[PRIVATE_KEY_1]` |
| UUIDs | `00000000-0000-4000-8000-000000000001` |
| Hex strings >= 32 chars (session ids, hashes) | `[HEX_1]` |
| Opaque high-entropy values in fields (`state`, `code`, nonces) | `[BLOB_1]` |
| Credit cards (Luhn-checked), SSNs, phone numbers | `[CARD_1]`, `[SSN_1]`, `[PHONE_1]` |
| Client terms you pass with `-t` / config | `[CLIENT_1]` |

Kept on purpose so the LLM has context: HTTP method, path, header names,
`Server`, `User-Agent`, `Content-Type`, status codes, non-sensitive JSON keys
and values, well-known third-party hosts (`cdnjs.cloudflare.com`, `w3.org`...).
`Content-Length` is recomputed when the body changed.

## Configuration

`burp-anon config --init` writes `~/.config/burp-anon/config.json`. Lists in it
are merged with the defaults; prefix a key with `!` to replace instead:

```json
{
  "terms": ["Acme Corp", "acme", "project-falcon"],
  "keep_hosts": ["my-vps.example.net"],
  "keep_private_ips": true,
  "sensitive_key_substrings": ["employeeid"],
  "nonsensitive_keys": ["name"],
  "keep_cookies": ["lang"],
  "secret_patterns": ["ACME-[A-Z0-9]{20}"],
  "detect": {"phone": false}
}
```

Flags override per run: `-t WORD`, `-k HOST`, `--keep-private-ips`,
`--disable phone`, `--no-update-content-length`, `--no-save` (one-shot, not
restorable), `--show-map` (prints the new mappings to stderr).

## Caveats

- Free-text names (a person's name in a paragraph of HTML) are not detected
  unless they sit in a field with a sensitive name. Add them with `-t`.
- Hostnames in free text are only mapped when the TLD is known (so `jquery.min.js`
  is left alone). Host headers and URLs are always mapped.
- Base64-encoded or compressed bodies are not decoded. Let Burp show you the
  decoded body before copying, or add a `secret_patterns` entry.
- The map file holds the originals. Treat `~/.burp-anon/` like a credential store.
- Always eyeball the output before pasting. This reduces risk; it does not
  replace judgement.

## Tests

```bash
python3 -m unittest discover -s Utils/burp_anon/tests -v
```
