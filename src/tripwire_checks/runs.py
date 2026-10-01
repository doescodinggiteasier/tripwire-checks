"""Running checks honestly: exit-status receipts, command lint, and negative controls."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

SKIP_RC = 77  # a check exits 77 to say "this environment cannot evaluate me"; a SKIP is never a PASS


def sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_sha(cwd=None) -> str | None:
    try:
        p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cwd, capture_output=True, text=True, timeout=10)
        return p.stdout.strip() or None if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


# -- lint ----------------------------------------------------------------------------------------
LINT_RULES = [
    ("trailing-echo", re.compile(r";\s*echo\s+\$\?\s*$"),
     "`cmd; echo $?` exits 0 because the echo succeeds; the reported status is the echo's"),
    ("pipe-masks-exit", re.compile(r"\|\s*(tail|head|grep|tee|sort|wc|less|cat)\b"),
     "a pipeline's status is its last command's; use `set -o pipefail` or ${PIPESTATUS[0]}"),
    ("unquoted-glob", re.compile(r"--include=(?![\"'])\S*\*"),
     "an unquoted glob in an option may never expand (zsh) or expand against the cwd"),
    ("or-true", re.compile(r"\|\|\s*(true|:)\s*$"),
     "`|| true` turns every failure into success"),
]


def lint(cmd: str) -> list[tuple[str, str]]:
    """Problems that make a command's exit status lie. Empty list = clean."""
    out = []
    guarded = "pipefail" in cmd or "PIPESTATUS" in cmd
    for name, rx, why in LINT_RULES:
        if name == "pipe-masks-exit" and guarded:
            continue
        if rx.search(cmd):
            out.append((name, why))
    return out


# -- receipts ------------------------------------------------------------------------------------
def run(cmd: str, *, cwd=None, inputs=(), receipt_path=None, timeout=None, shell="/bin/bash", strict_lint=True) -> dict:
    """Run `cmd` under bash with pipefail, capture its real exit code, and write a receipt.

    The receipt records the command, exit code, UTC time, git sha of `cwd`, sha256 of each input
    file, lint findings and the last lines of output. With `strict_lint`, a command whose exit
    status could be masked is refused before it runs (exit code 2 in the receipt)."""
    problems = lint(cmd)
    rec = dict(command=cmd, cwd=str(Path(cwd or os.getcwd()).resolve()),
               started=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
               git_sha=git_sha(cwd), inputs={str(p): sha256(p) for p in inputs}, lint=problems)
    if problems and strict_lint:
        rec.update(exit=2, verdict="REFUSED", stdout_tail="", stderr_tail="lint: " + "; ".join(n for n, _ in problems))
    else:
        try:
            p = subprocess.run([shell, "-o", "pipefail", "-c", cmd], cwd=cwd, capture_output=True, text=True, timeout=timeout)
            rc, so, se = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            rc, so, se = 124, e.stdout or "", f"timed out after {timeout}s"
            so = so.decode() if isinstance(so, bytes) else so
        rec.update(exit=rc, verdict="PASS" if rc == 0 else ("SKIP" if rc == SKIP_RC else "FAIL"),
                   stdout_tail="\n".join((so or "").strip().splitlines()[-5:]),
                   stderr_tail="\n".join((se or "").strip().splitlines()[-5:]))
    rec["finished"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    if receipt_path:
        Path(receipt_path).parent.mkdir(parents=True, exist_ok=True)
        Path(receipt_path).write_text(json.dumps(rec, indent=1) + "\n")
    return rec


# -- negative control ----------------------------------------------------------------------------
def negative_control(cmd: str, *, cwd=None, corrupt=None, include=None, timeout=120, shell="/bin/bash") -> dict:
    """Run a check where it MUST fail, then where it should pass.

    1. In an empty temporary directory (absolute paths in `cmd` still resolve, so a check that
       reads only its own fixed inputs is caught by step 2 instead).
    2. If `corrupt` is given (a function that receives a temp copy of `cwd` and damages it), the
       check is run against the corrupted copy. `include` (relative paths) limits the copy to
       what the check reads, for large working trees.
    3. In `cwd` itself.

    Verdict: VACUOUS if the check passed in any must-fail run; PASS if it failed there and passed
    for real; FAIL if the real run failed. A check that cannot fail is never reported as PASS."""
    def go(where):
        p = subprocess.run([shell, "-o", "pipefail", "-c", cmd], cwd=where, capture_output=True, text=True, timeout=timeout)
        return p.returncode

    out = dict(command=cmd, controls={})
    with tempfile.TemporaryDirectory() as empty:
        out["controls"]["empty_dir"] = go(empty)
    if corrupt is not None:
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(cwd or os.getcwd()), Path(tmp) / "copy"
            if include is None:
                shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns(".git"))
            else:
                for rel in include:
                    (dst / rel).parent.mkdir(parents=True, exist_ok=True)
                    (shutil.copytree if (src / rel).is_dir() else shutil.copy2)(src / rel, dst / rel)
            corrupt(dst)
            out["controls"]["corrupted"] = go(dst)
    out["real"] = go(cwd)
    vacuous = [k for k, rc in out["controls"].items() if rc == 0]
    if out["real"] != 0:
        out["verdict"] = "FAIL"
    elif vacuous:
        out["verdict"] = "VACUOUS"
        out["why"] = f"passed where it must fail: {', '.join(vacuous)}"
    else:
        out["verdict"] = "PASS"
    return out


def quote(*args) -> str:
    return " ".join(shlex.quote(str(a)) for a in args)
