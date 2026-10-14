"""Minimal cross-platform clipboard access (macOS, X11, Wayland, Windows)."""
import platform
import shutil
import subprocess

_SYS = platform.system()


def _cmds():
    if _SYS == "Darwin":
        return (["pbpaste"], ["pbcopy"])
    if _SYS == "Windows":
        return (["powershell", "-NoProfile", "-Command", "Get-Clipboard"], ["clip"])
    if shutil.which("wl-paste") and shutil.which("wl-copy"):
        return (["wl-paste", "--no-newline"], ["wl-copy"])
    if shutil.which("xclip"):
        return (["xclip", "-selection", "clipboard", "-o"], ["xclip", "-selection", "clipboard"])
    if shutil.which("xsel"):
        return (["xsel", "--clipboard", "--output"], ["xsel", "--clipboard", "--input"])
    raise SystemExit("no clipboard tool found (install xclip, xsel or wl-clipboard)")


def read():
    paste, _ = _cmds()
    return subprocess.run(paste, capture_output=True, check=True).stdout.decode("utf-8", "replace")


def write(text):
    _, copy = _cmds()
    subprocess.run(copy, input=text.encode("utf-8"), check=True)
