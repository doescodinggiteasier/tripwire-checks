"""Preconditions, calibration and counts: an analysis proves its own checks can fail.

Everything is recorded in a `Ledger`. A module-level default ledger backs the plain functions
(`require`, `stamp`, `calibrate`, ...) so a script can use them without ceremony; pass your own
`Ledger()` when several analyses share a process.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable


class PreconditionViolated(SystemExit):
    """Raised (exit code 3) when a precondition fails. Deliberately not a warning."""

    def __init__(self, name: str, detail: str = ""):
        super().__init__(3)
        self.name, self.detail = name, detail

    def __str__(self) -> str:
        return f"precondition failed: {self.name}" + (f" ({self.detail})" if self.detail else "")


@dataclass
class Case:
    """One known case for calibration: `value` is what the detector sees, `expect` whether it should fire.
    `ref` points at the real row it came from, so anyone can look the label up and disagree with it."""
    ref: str
    value: object
    expect: bool
    why: str = ""


@dataclass
class Ledger:
    passed: list = field(default_factory=list)
    bypassed: list = field(default_factory=list)
    calibrations: list = field(default_factory=list)
    measurements: list = field(default_factory=list)
    counts: list = field(default_factory=list)

    # -- preconditions -------------------------------------------------------------------------
    def require(self, name: str, cond: bool, detail: str = "") -> None:
        """Assert a precondition; abort on violation. Passing names are kept for `stamp()`."""
        if not cond:
            print(f"ABORTED: precondition failed: {name}" + (f"\n  {detail}" if detail else ""), file=sys.stderr)
            raise PreconditionViolated(name, detail)
        if name not in self.passed:
            self.passed.append(name)

    def bypass(self, name: str, detail: str = "") -> None:
        """Record a precondition deliberately waived. It is listed apart from verified ones, always."""
        self.bypassed.append(name + (f" ({detail})" if detail else ""))

    # -- calibration ---------------------------------------------------------------------------
    def calibrate(self, name: str, cases: Iterable[Case], fn: Callable[[object], bool], *,
                  bar: float = 1.0, min_each: int = 5) -> dict:
        """Score detector `fn` on known cases; abort unless there are >= `min_each` true AND false
        cases and accuracy >= `bar`. Returns the receipt, which `count()` and `stamp()` rely on."""
        cases = list(cases)
        t = [c for c in cases if c.expect]
        f = [c for c in cases if not c.expect]
        self.require(f"calibration {name}: >= {min_each} known-true cases", len(t) >= min_each,
                     f"{len(t)} given")
        self.require(f"calibration {name}: >= {min_each} known-false cases", len(f) >= min_each,
                     f"{len(f)} given; a detector checked only on positives drifts toward yes unseen")
        self.require(f"calibration {name}: every case has a ref", all(c.ref for c in cases))
        misses = []
        for c in cases:
            try:
                got = bool(fn(c.value))
            except Exception as e:  # a detector that raises is wrong on that case
                misses.append((c.ref, f"raised {type(e).__name__}"))
                continue
            if got != c.expect:
                misses.append((c.ref, "fired" if got else "silent"))
        acc = 1 - len(misses) / len(cases)
        self.require(f"calibration {name}: accuracy >= {bar:.0%}", acc >= bar,
                     f"{acc:.0%} on {len(cases)} cases; misses {misses[:5]}")
        rec = dict(name=name, n=len(cases), true=len(t), false=len(f), accuracy=acc, bar=bar, misses=misses)
        self.calibrations.append(rec)
        return rec

    def measure(self, name: str, cases: Iterable[Case], fn: Callable[[object], bool]) -> dict:
        """Report accuracy without aborting and without granting a receipt (so `count()` still refuses).
        Use it to learn that a detector detects nothing."""
        cases = list(cases)
        fires = [(c, _safe(fn, c.value)) for c in cases]
        rec = dict(name=name, n=len(cases),
                   accuracy=sum(g == c.expect for c, g in fires) / len(cases) if cases else 0.0,
                   fires_on_true=sum(g for c, g in fires if c.expect),
                   fires_on_false=sum(g for c, g in fires if not c.expect))
        self.measurements.append(rec)
        return rec

    def count(self, n, what: str):
        """Return `n`, but only if a calibration receipt exists in this ledger; abort otherwise."""
        self.require(f"a calibration receipt exists before counting {what!r}", bool(self.calibrations),
                     "a count is worth what its detector is worth on cases whose answer is known")
        self.counts.append(f"{what}={n}")
        return n

    # -- stamp ---------------------------------------------------------------------------------
    def stamp(self) -> str:
        """One line to embed in an output: what was verified, calibrated, merely measured, or waived."""
        if self.counts and not self.calibrations:
            self.require("every count has a calibration receipt", False)
        s = "preconditions verified: " + (", ".join(self.passed) if self.passed else "NONE (unverified output)")
        if self.calibrations:
            s += " | calibrated: " + "; ".join(
                f"{c['name']} {c['accuracy']:.0%} on {c['n']} ({c['true']}T/{c['false']}F, bar {c['bar']:.0%})"
                for c in self.calibrations)
        if self.measurements:
            s += " | measured, not a receipt: " + "; ".join(
                f"{m['name']} {m['accuracy']:.0%} (fires on {m['fires_on_true']} true, {m['fires_on_false']} false)"
                for m in self.measurements)
        if self.bypassed:
            s += " | BYPASSED (not verified): " + ", ".join(self.bypassed)
        return s


def _safe(fn, v) -> bool:
    try:
        return bool(fn(v))
    except Exception:
        return False


DEFAULT = Ledger()
require = DEFAULT.require
bypass = DEFAULT.bypass
calibrate = DEFAULT.calibrate
measure = DEFAULT.measure
count = DEFAULT.count
stamp = DEFAULT.stamp
