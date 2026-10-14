"""Read/write Burp Suite 'Save items' XML exports (Proxy history, Sitemap, Repeater)."""
import base64
import xml.etree.ElementTree as ET


def _decode(el):
    if el is None or el.text is None:
        return ""
    if el.get("base64", "false").lower() == "true":
        return base64.b64decode(el.text).decode("utf-8", "replace")
    return el.text


def _encode(el, text):
    el.text = base64.b64encode(text.encode("utf-8")).decode()
    el.set("base64", "true")


def anonymize_items(xml_text, anon):
    """Returns (text_dump, anonymized_xml_string)."""
    root = ET.fromstring(xml_text)
    dump = []
    for i, item in enumerate(root.findall("item"), 1):
        url_el, host_el = item.find("url"), item.find("host")
        req_el, res_el = item.find("request"), item.find("response")
        url = anon.url(url_el.text.strip()) if url_el is not None and url_el.text else ""
        if url_el is not None:
            url_el.text = url
        if host_el is not None:
            if host_el.text:
                host_el.text = anon.host(host_el.text.strip())
            if host_el.get("ip"):
                host_el.set("ip", anon.ipv4(host_el.get("ip")))
        req = anon.anonymize(_decode(req_el)) if req_el is not None else ""
        res = anon.anonymize(_decode(res_el)) if res_el is not None else ""
        if req_el is not None:
            _encode(req_el, req)
        if res_el is not None:
            _encode(res_el, res)
        for tag in ("comment", "path", "extension", "mimetype"):
            el = item.find(tag)
            if el is not None and el.text:
                el.text = anon.text(el.text)
        status = item.findtext("status") or ""
        method = item.findtext("method") or ""
        dump.append("=" * 20 + " item %d: %s %s %s " % (i, method, url, status) + "=" * 20)
        dump.append(req.rstrip("\r\n"))
        if res.strip():
            dump.append("")
            dump.append(res.rstrip("\r\n"))
        dump.append("")
    return "\n".join(dump), ET.tostring(root, encoding="unicode")
