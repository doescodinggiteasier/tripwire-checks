"""Every check is tested in both directions: it passes what it should AND fails what it must
(each check's own negative control)."""
import json
import os
import sys

import pytest

import tripwire_checks as tw
from tripwire_checks import prereg
from tripwire_checks.cli import main as cli


# 1. preconditions
def test_require_passes_and_is_stamped():
    L = tw.Ledger()
    L.require("input has rows", True)
    assert "input has rows" in L.stamp()


def test_require_aborts():  # negative control
    L = tw.Ledger()
    with pytest.raises(tw.PreconditionViolated) as e:
        L.require("input has rows", False, "0 rows")
    assert e.value.code == 3


def test_unverified_and_bypassed_are_visible():
    L = tw.Ledger()
    assert "NONE (unverified output)" in L.stamp()
    L.require("a", True); L.bypass("blind", "--allow-leak")
    s = L.stamp()
    assert "BYPASSED (not verified): blind (--allow-leak)" in s and s.index("verified: a") < s.index("BYPASSED")


# 2. negative control
def test_negative_control_flags_vacuous_check(tmp_path):
    # a check that cannot fail: `test 0 -eq 0` passes anywhere
    res = tw.negative_control("test 0 -eq 0", cwd=tmp_path)
    assert res["verdict"] == "VACUOUS"


def test_negative_control_passes_real_check(tmp_path):
    (tmp_path / "data.csv").write_text("a\n1\n2\n")
    res = tw.negative_control("test $(wc -l < data.csv) -eq 3", cwd=tmp_path)
    assert res["verdict"] == "PASS" and res["controls"]["empty_dir"] != 0


def test_negative_control_unquoted_glob_bug(tmp_path):
    # the classic: grep finds nothing because the glob never matches, count is 0, `-eq 0` passes
    (tmp_path / "a.md").write_text("TODO\n")
    cmd = "test $(grep -rl TODO --include=*.txt . | wc -l) -eq 0"
    assert tw.negative_control(cmd, cwd=tmp_path)["verdict"] == "VACUOUS"


def test_negative_control_with_corruption(tmp_path):
    (tmp_path / "data.csv").write_text("a\n1\n")
    res = tw.negative_control("test -s data.csv", cwd=tmp_path,
                              corrupt=lambda d: (d / "data.csv").write_text(""))
    assert res["verdict"] == "PASS" and res["controls"]["corrupted"] != 0
    res = tw.negative_control("test -e data.csv", cwd=tmp_path,
                              corrupt=lambda d: (d / "data.csv").write_text(""))
    assert res["verdict"] == "VACUOUS"   # passes on the corrupted copy: it checks existence, not content


# 3. receipts and lint
def test_receipt_records_real_exit(tmp_path):
    rec = tw.run("exit 7", receipt_path=tmp_path / "r.json", cwd=tmp_path)
    assert rec["exit"] == 7 and rec["verdict"] == "FAIL"
    assert json.loads((tmp_path / "r.json").read_text())["exit"] == 7


def test_pipefail_exposes_masked_failure(tmp_path):
    rec = tw.run("false | cat", cwd=tmp_path, strict_lint=False)
    assert rec["exit"] != 0          # without pipefail this would report 0


@pytest.mark.parametrize("cmd,rule", [("make test; echo $?", "trailing-echo"), ("pytest | tail -3", "pipe-masks-exit"),
                                      ("grep -r x --include=*.md .", "unquoted-glob"), ("./check.sh || true", "or-true")])
def test_lint_catches(cmd, rule):
    assert rule in [n for n, _ in tw.lint(cmd)]


@pytest.mark.parametrize("cmd", ["pytest -q", "set -o pipefail; pytest | tail -3", "grep -r x --include='*.md' ."])
def test_lint_clean(cmd):
    assert tw.lint(cmd) == []


def test_strict_lint_refuses_to_run(tmp_path):
    rec = tw.run("touch ran; echo $?", cwd=tmp_path)
    assert rec["verdict"] == "REFUSED" and not (tmp_path / "ran").exists()


def test_skip_is_not_pass(tmp_path):
    assert tw.run("exit 77", cwd=tmp_path)["verdict"] == "SKIP"


def test_input_hashes(tmp_path):
    f = tmp_path / "in.txt"; f.write_text("x")
    assert tw.run("true", cwd=tmp_path, inputs=[f])["inputs"][str(f)] == tw.sha256(f)


# 4. calibration
def cases(n_true, n_false):
    return [tw.Case(f"t{i}", 10 + i, True) for i in range(n_true)] + [tw.Case(f"f{i}", i, False) for i in range(n_false)]


def test_calibrate_receipt_and_count():
    L = tw.Ledger()
    rec = L.calibrate("big", cases(5, 5), lambda v: v >= 10)
    assert rec["accuracy"] == 1.0 and L.count(42, "big rows") == 42
    assert "calibrated: big 100% on 10 (5T/5F" in L.stamp()


def test_calibrate_needs_false_cases():  # negative control: positives only
    with pytest.raises(tw.PreconditionViolated):
        tw.Ledger().calibrate("big", cases(10, 2), lambda v: v >= 10)


def test_calibrate_rejects_detector_that_always_fires():
    with pytest.raises(tw.PreconditionViolated):
        tw.Ledger().calibrate("big", cases(5, 5), lambda v: True)


def test_count_refuses_without_receipt():
    L = tw.Ledger()
    L.measure("big", cases(5, 5), lambda v: True)   # measuring does not grant a receipt
    with pytest.raises(tw.PreconditionViolated):
        L.count(3, "rows")
    assert "fires on 5 true, 5 false" in L.stamp()


# 5. shuffled-label control
def test_shuffled_control_exposes_lenient_judge():
    labels = [1] * 90 + [0] * 10
    lenient = [1] * 100                       # says yes to everything: 90% "accuracy"
    r = tw.shuffled_control(lenient, labels, n=500)
    assert r["real"] == 0.9 and r["shuffled_mean"] == pytest.approx(0.9) and r["p_value"] > 0.5


def test_shuffled_control_credits_real_judge():
    labels = [1, 0] * 50
    r = tw.shuffled_control(labels, labels, n=500)
    assert r["real"] == 1.0 and r["p_value"] < 0.01 and r["lift"] > 0.4


# 6. pre-registration
def test_prereg_detects_unlogged_change(tmp_path):
    p, led = tmp_path / "PREREG.md", tmp_path / "hashes.txt"
    p.write_text("H1: x > y\n")
    prereg.register(p, led, "v1 before data")
    L = tw.Ledger()
    prereg.check(p, led, L.require)
    p.write_text("H1: x < y\n")       # edited after seeing results
    with pytest.raises(tw.PreconditionViolated):
        prereg.check(p, led, L.require)
    prereg.register(p, led, "A1: deviation, direction flipped after pilot")
    prereg.check(p, led, L.require)


def test_prereg_register_needs_note(tmp_path):
    p = tmp_path / "P.md"; p.write_text("x")
    with pytest.raises(ValueError):
        prereg.register(p, tmp_path / "h.txt", " ")


# CLI
def test_cli_lint_and_negctl(tmp_path, capsys):
    assert cli(["lint", "pytest | tail -1"]) == 1
    assert cli(["negctl", "true", "--cwd", str(tmp_path)]) == 1
    assert cli(["run", "exit 3", "--receipt", str(tmp_path / "r.json")]) == 3
