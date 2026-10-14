"""burp-anon command line.

  burp-anon [anon] [FILE...]  anonymize (default). No FILE -> stdin; -c -> clipboard
  burp-anon restore [FILE]    put the originals back into LLM output
  burp-anon xml FILE          anonymize a Burp "Save items" XML export
  burp-anon watch             poll the clipboard and anonymize whatever lands on it
  burp-anon map               show / clear / export the session mapping
  burp-anon config            print config path, or write a starter config (--init)
"""
import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .anonymizer import Anonymizer
from .config import DEFAULT_CONFIG_PATH, DEFAULT_MAP_DIR, load_config, write_default_config
from .mapping import Mapping

SUBCOMMANDS = ("anon", "restore", "xml", "watch", "map", "config")


def _map_path(args):
    if args.map:
        return Path(args.map).expanduser()
    return DEFAULT_MAP_DIR / (args.session + ".json")


def _build(args):
    cfg = load_config(args.config)
    if getattr(args, "term", None):
        cfg["terms"] = list(dict.fromkeys(cfg["terms"] + args.term))
    if getattr(args, "keep", None):
        cfg["keep_hosts"] = list(dict.fromkeys(cfg["keep_hosts"] + args.keep))
    if getattr(args, "keep_private_ips", False):
        cfg["keep_private_ips"] = True
    if getattr(args, "no_update_content_length", False):
        cfg["update_content_length"] = False
    for name in getattr(args, "disable", None) or []:
        cfg.setdefault("detect", {})[name] = False
    mapping = Mapping(None if getattr(args, "no_save", False) else _map_path(args))
    return Anonymizer(mapping, cfg), mapping


def _read_input(args):
    if getattr(args, "clip", False):
        from . import clipboard
        return clipboard.read()
    files = getattr(args, "files", None) or []
    if files:
        return "\n\n".join(Path(f).read_bytes().decode("utf-8", "replace") for f in files)
    if sys.stdin.isatty():
        print("reading from stdin (Ctrl-D to finish)...", file=sys.stderr)
    return sys.stdin.buffer.read().decode("utf-8", "replace")  # keep CRLF intact


def _write_output(args, text):
    if getattr(args, "clip", False):
        from . import clipboard
        clipboard.write(text)
        print("-> clipboard (%d chars)" % len(text), file=sys.stderr)
    elif getattr(args, "output", None):
        Path(args.output).write_bytes(text.encode("utf-8"))
        print("-> %s" % args.output, file=sys.stderr)
    else:
        sys.stdout.buffer.write(text.encode("utf-8"))
        if not text.endswith("\n"):
            sys.stdout.buffer.write(b"\n")
        sys.stdout.flush()


def _add_common(p):
    p.add_argument("-s", "--session", default="default", help="mapping session name (default: default)")
    p.add_argument("-m", "--map", help="explicit mapping file path (overrides --session)")
    p.add_argument("--config", help="config JSON path (default: %s)" % DEFAULT_CONFIG_PATH)


def _add_anon_opts(p):
    p.add_argument("-c", "--clip", action="store_true", help="read from and write to the clipboard")
    p.add_argument("-o", "--output", help="write result to file")
    p.add_argument("-t", "--term", action="append", metavar="WORD",
                   help="client-identifying word to replace (repeatable)")
    p.add_argument("-k", "--keep", action="append", metavar="HOST", help="host to keep verbatim (repeatable)")
    p.add_argument("--keep-private-ips", action="store_true", help="leave RFC1918/loopback IPs alone")
    p.add_argument("--disable", action="append", metavar="DETECTOR",
                   help="turn off a detector: jwt,url,email,host,ipv4,ipv6,uuid,hex,card,ssn,phone,blob,secrets,terms")
    p.add_argument("--no-update-content-length", action="store_true")
    p.add_argument("--no-save", action="store_true", help="do not persist the mapping (one-shot, not restorable)")
    p.add_argument("--show-map", action="store_true", help="print new mapping entries to stderr (contains secrets!)")


def build_parser():
    ap = argparse.ArgumentParser(prog="burp-anon", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-V", "--version", action="version", version="burp-anon " + __version__)
    sub = ap.add_subparsers(dest="cmd")

    a = sub.add_parser("anon", help="anonymize requests/responses (default)")
    a.add_argument("files", nargs="*", help="raw HTTP files (default: stdin)")
    _add_common(a); _add_anon_opts(a)

    r = sub.add_parser("restore", help="replace placeholders with originals")
    r.add_argument("files", nargs="*")
    r.add_argument("-c", "--clip", action="store_true")
    r.add_argument("-o", "--output")
    _add_common(r)

    x = sub.add_parser("xml", help="anonymize a Burp 'Save items' XML export")
    x.add_argument("file")
    x.add_argument("--xml-out", help="also write an anonymized XML copy (re-importable into Burp)")
    _add_common(x); _add_anon_opts(x)

    w = sub.add_parser("watch", help="poll the clipboard; anonymize new content in place")
    w.add_argument("--interval", type=float, default=0.7)
    _add_common(w); _add_anon_opts(w)

    mp = sub.add_parser("map", help="inspect the session mapping")
    g = mp.add_mutually_exclusive_group()
    g.add_argument("--show", action="store_true", help="print placeholder -> original (secrets!)")
    g.add_argument("--clear", action="store_true", help="delete the session mapping")
    g.add_argument("--export", metavar="FILE", help="copy the mapping JSON to FILE")
    _add_common(mp)

    cf = sub.add_parser("config", help="config file helpers")
    cf.add_argument("--init", action="store_true", help="write a starter config file")
    cf.add_argument("--config")
    return ap


def cmd_anon(args):
    anon, mapping = _build(args)
    before = set(mapping.reverse)
    text = _read_input(args)
    out = anon.anonymize(text)
    mapping.save()
    _write_output(args, out)
    print("replaced: %s | map: %s" % (anon.summary(), mapping.path or "(not saved)"), file=sys.stderr)
    if args.show_map:
        for ph, orig in mapping.reverse.items():
            if ph not in before:
                print("  %s  <-  %s" % (ph, orig), file=sys.stderr)
    return 0


def cmd_restore(args):
    mapping = Mapping(_map_path(args))
    if not len(mapping):
        print("mapping is empty: %s" % mapping.path, file=sys.stderr)
    text = _read_input(args)
    _write_output(args, mapping.restore(text))
    return 0


def cmd_xml(args):
    from .burp_xml import anonymize_items
    anon, mapping = _build(args)
    xml_text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    dump, new_xml = anonymize_items(xml_text, anon)
    mapping.save()
    _write_output(args, dump)
    if args.xml_out:
        Path(args.xml_out).write_text(new_xml, encoding="utf-8")
        print("-> %s" % args.xml_out, file=sys.stderr)
    print("replaced: %s | map: %s" % (anon.summary(), mapping.path or "(not saved)"), file=sys.stderr)
    return 0


def cmd_watch(args):
    from . import clipboard
    anon, mapping = _build(args)
    last = clipboard.read()
    print("watching clipboard (session %s). Copy from Burp, paste into your LLM. Ctrl-C to stop."
          % (mapping.path.stem if mapping.path else "ephemeral"), file=sys.stderr)
    try:
        while True:
            time.sleep(args.interval)
            try:
                cur = clipboard.read()
            except Exception:
                continue
            if cur == last or not cur.strip():
                continue
            anon.stats.clear()
            out = anon.anonymize(cur)
            mapping.save()
            if out != cur:
                clipboard.write(out)
            last = out
            print("[%s] %d chars, %s" % (time.strftime("%H:%M:%S"), len(cur), anon.summary()), file=sys.stderr)
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
    return 0


def cmd_map(args):
    path = _map_path(args)
    mapping = Mapping(path)
    if args.clear:
        if path.exists():
            path.unlink()
            print("deleted %s" % path, file=sys.stderr)
        else:
            print("no mapping at %s" % path, file=sys.stderr)
        return 0
    if args.export:
        Path(args.export).write_text(path.read_text(encoding="utf-8") if path.exists() else "{}", encoding="utf-8")
        print("-> %s" % args.export, file=sys.stderr)
        return 0
    print("map file: %s (%d entries)" % (path, len(mapping)))
    if args.show:
        for cat, orig, ph in mapping.entries():
            print("%-32s %-10s %s" % (ph, cat, orig))
    else:
        from collections import Counter
        counts = Counter(cat for cat, _, _ in mapping.entries())
        for cat, n in sorted(counts.items()):
            print("  %-12s %d" % (cat, n))
    return 0


def cmd_config(args):
    if args.init:
        p = write_default_config(args.config)
        print("wrote %s" % p)
    else:
        print(DEFAULT_CONFIG_PATH, "(exists)" if DEFAULT_CONFIG_PATH.exists() else "(not present, defaults in use)")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help", "-V", "--version"):
        argv.insert(0, "anon")
    args = build_parser().parse_args(argv)
    return {"anon": cmd_anon, "restore": cmd_restore, "xml": cmd_xml, "watch": cmd_watch,
            "map": cmd_map, "config": cmd_config}[args.cmd](args)
