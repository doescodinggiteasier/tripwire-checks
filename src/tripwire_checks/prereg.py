"""Pre-registration guard: an analysis refuses to run if its pre-registration changed without a logged deviation.

Hashes live in a plain-text ledger, one line per registered state:
    <sha256>  <file>  <utc time>  <note>
`register()` appends a line. `check()` passes only when the file's current hash is on the ledger,
so every edit after registration must be registered again with a note (a deviation, an addendum),
which leaves the history in the ledger rather than in a diff nobody reads."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from .core import require
from .runs import sha256


def _lines(ledger):
    p = Path(ledger)
    return [l.split() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")] if p.exists() else []


def register(prereg, ledger, note: str) -> str:
    """Record the current hash of `prereg` with a note (required). Returns the hash."""
    if not note.strip():
        raise ValueError("a registration needs a note saying what changed and why")
    h = sha256(prereg)
    t = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    with open(ledger, "a") as f:
        f.write(f"{h}  {Path(prereg).name}  {t}  {note.strip()}\n")
    return h


def check(prereg, ledger, require_fn=require) -> str:
    """Abort unless the current hash of `prereg` was registered. Returns the hash."""
    h = sha256(prereg)
    known = {row[0] for row in _lines(ledger) if row}
    require_fn(f"pre-registration {Path(prereg).name} unchanged since registration", h in known,
               f"current sha256 {h[:12]}… is not in {ledger}; log the change with "
               f"`tripwire prereg register {prereg} {ledger} --note '...'` before running")
    return h
