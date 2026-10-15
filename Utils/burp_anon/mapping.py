"""Persistent, consistent, reversible pseudonym store.

Every original value that gets redacted is mapped to exactly one placeholder
for the lifetime of a session (map file). The same host/token/email seen in
twenty requests always becomes the same placeholder, so an LLM can still
reason about relationships between values. The map file is the only place
the originals live, so guard it (it is written mode 0600).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Callable, Iterator, Optional, Union


class Mapping:
    def __init__(self, path: Optional[Union[str, Path]] = None) -> None:
        self.path: Optional[Path] = Path(path).expanduser() if path else None
        self.forward: dict[str, dict[str, str]] = {}  # category -> {original: placeholder}
        self.reverse: dict[str, str] = {}  # placeholder -> original
        self.counters: dict[str, int] = {}  # category -> last counter used
        self.dirty = False
        self._restore_re: Optional[re.Pattern[str]] = None
        if self.path and self.path.exists():
            self.load()

    # ---- persistence -----------------------------------------------------
    def load(self) -> None:
        assert self.path is not None
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.forward = data.get("forward", {})
        self.counters = data.get("counters", {})
        self.reverse = {ph: orig for cat in self.forward.values() for orig, ph in cat.items()}
        self._restore_re = None

    def save(self) -> None:
        # Directory ownership: this method is the *sole writer* of a session map
        # file (~/.burp-anon/sessions/<name>.json). Files are addressed by session
        # name, never ordered by mtime, so the only invariant is the atomic
        # temp-write + chmod 0600 + replace below. Any other writer to that
        # directory would be a breaking change.
        if not self.path or not self.dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        payload = {"forward": self.forward, "counters": self.counters}
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        self.dirty = False

    def clear(self) -> None:
        self.forward, self.reverse, self.counters = {}, {}, {}
        self.dirty = True
        self._restore_re = None

    # ---- lookup ----------------------------------------------------------
    def is_placeholder(self, value: str) -> bool:
        return value in self.reverse

    def get(self, category: str, original: str, make: Callable[[int], str]) -> str:
        """Return the placeholder for `original` in `category`, creating it if
        needed. `make(n)` builds a placeholder from the per-category counter."""
        if original in self.reverse:  # already a placeholder: leave it
            return original
        cat = self.forward.setdefault(category, {})
        if original in cat:
            return cat[original]
        n = self.counters.get(category, 0) + 1
        self.counters[category] = n
        ph = make(n)
        cat[original] = ph
        self.reverse[ph] = original
        self.dirty = True
        self._restore_re = None
        return ph

    def __len__(self) -> int:
        return len(self.reverse)

    def entries(self) -> Iterator[tuple[str, str, str]]:
        for cat, pairs in sorted(self.forward.items()):
            for orig, ph in pairs.items():
                yield cat, orig, ph

    # ---- restore ---------------------------------------------------------
    def restore(self, text: str) -> str:
        """Replace every known placeholder in `text` with its original value."""
        if not self.reverse:
            return text
        if self._restore_re is None:
            parts = []
            for ph in sorted(self.reverse, key=len, reverse=True):
                pat = re.escape(ph)
                if ph[0].isalnum():
                    pat = r"(?<![A-Za-z0-9])" + pat
                if ph[-1].isalnum():
                    pat = pat + r"(?![A-Za-z0-9])"
                parts.append(pat)
            self._restore_re = re.compile("|".join(parts))
        return self._restore_re.sub(lambda m: self.reverse.get(m.group(0), m.group(0)), text)
