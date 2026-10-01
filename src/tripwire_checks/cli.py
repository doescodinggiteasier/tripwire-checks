"""Command line: `tripwire run|negctl|lint|prereg ...`."""
from __future__ import annotations

import argparse
import json
import sys

from . import prereg, runs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tripwire", description="Make checks prove they can fail.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a command and write an exit-status receipt")
    r.add_argument("command"); r.add_argument("--receipt", required=True); r.add_argument("--input", action="append", default=[])
    r.add_argument("--allow-lint", action="store_true", help="run even if lint finds masking (recorded in the receipt)")
    n = sub.add_parser("negctl", help="run a check in an empty directory, then for real; VACUOUS if it cannot fail")
    n.add_argument("command"); n.add_argument("--cwd", default=None)
    li = sub.add_parser("lint", help="find exit-status masking in a command")
    li.add_argument("command")
    p = sub.add_parser("prereg", help="register or check a pre-registration hash")
    p.add_argument("action", choices=["register", "check"]); p.add_argument("file"); p.add_argument("ledger")
    p.add_argument("--note", default="")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        rec = runs.run(a.command, inputs=a.input, receipt_path=a.receipt, strict_lint=not a.allow_lint)
        print(f"{rec['verdict']} exit={rec['exit']} receipt={a.receipt}")
        return rec["exit"]
    if a.cmd == "negctl":
        res = runs.negative_control(a.command, cwd=a.cwd)
        print(json.dumps(res, indent=1))
        return 0 if res["verdict"] == "PASS" else 1
    if a.cmd == "lint":
        probs = runs.lint(a.command)
        for name, why in probs:
            print(f"{name}: {why}")
        return 1 if probs else 0
    if a.action == "register":
        print(prereg.register(a.file, a.ledger, a.note))
        return 0
    print(prereg.check(a.file, a.ledger))
    return 0


if __name__ == "__main__":
    sys.exit(main())
