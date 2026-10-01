# tripwire-checks

Small, dependency-free Python checks that make an analysis pipeline **prove its own checks can fail**.

A check that cannot fail looks exactly like a check that passed. Most broken analyses I have seen were not wrong in their logic; they were wrong in a check that went green for a reason unrelated to the data: a glob that never expanded, a pipe that swallowed an exit code, a judge that said yes to everything. Each section below is one check: what it is, the failure it catches, and a short example.

```bash
pip install git+https://github.com/doescodinggiteasier/tripwire-checks@v0.1.0
```

Python ≥ 3.9, standard library only. MIT licensed.

## 1. Preconditions: `require` and `stamp`
**What:** `require(name, cond, detail)` aborts (exit 3) when a precondition fails, not a warning. `stamp()` returns one line listing every precondition that passed, to embed in the output, so an unverified or misconfigured run is visible in its own artifact.
**Catches:** a run that continues past a broken setup and produces confident output (a prompt template split on a marker that appears twice; an input file with zero rows).

```python
import tripwire_checks as tw

rows = load("weekly.csv")
tw.require("input has rows", len(rows) > 0, "weekly.csv is empty")
tw.require("one row per week", len({r["week"] for r in rows}) == len(rows))
tw.bypass("funding links", "--no-funding flag")   # waived, and listed apart from verified ones
result = analyse(rows)
result["verified"] = tw.stamp()
# 'preconditions verified: input has rows, one row per week | BYPASSED (not verified): funding links (--no-funding flag)'
```

## 2. Negative control: `negative_control`
**What:** runs a check where it must fail (an empty temporary directory, and optionally a corrupted copy of the inputs), then for real. A check that passes where it must fail is reported **VACUOUS**, never PASS.
**Catches:** checks whose green does not depend on the data, such as `test $(grep -rl TODO --include=*.txt . | wc -l) -eq 0`, which passes when the glob matches nothing.

```python
res = tw.negative_control("test $(wc -l < data.csv) -gt 1", cwd="analysis/")
assert res["verdict"] == "PASS"            # failed in the empty dir, passed for real

res = tw.negative_control("test -e data.csv", cwd="analysis/",
                          corrupt=lambda d: (d / "data.csv").write_text(""))
res["verdict"]                              # 'VACUOUS': it passed on an emptied file; it checks existence, not content
```
CLI: `tripwire negctl "pytest -q tests/test_counts.py" --cwd analysis/`

## 3. Exit-status receipts and lint: `run`, `lint`
**What:** `run(cmd, receipt_path=...)` runs the command under `bash -o pipefail`, records its real exit code, UTC time, git sha and the sha256 of each input, and writes a JSON receipt. Before running, `lint` refuses commands whose status can lie.
**Catches:** `cmd > log 2>&1; echo $?` (always 0: the echo's status), `pytest | tail -3` (the tail's status), `|| true`, unquoted globs in options.

```python
rec = tw.run("python3 -m pytest -q", receipt_path="receipts/tests.json", inputs=["data/weekly.csv"])
rec["exit"], rec["verdict"]                 # (0, 'PASS'); 77 is reported as 'SKIP', never 'PASS'

tw.lint("pytest | tail -3")                 # [('pipe-masks-exit', "a pipeline's status is its last command's; ...")]
tw.run("make test; echo $?")["verdict"]     # 'REFUSED' (not run)
```
CLI: `tripwire run "pytest -q" --receipt receipts/tests.json --input data/weekly.csv`

## 4. Calibration receipts: `calibrate`, `measure`, `count`
**What:** `calibrate(name, cases, fn, bar)` scores a detector on known cases and aborts unless there are at least 5 known-true **and** 5 known-false cases and accuracy meets a bar you state up front. `count()` refuses to report a number until a calibration receipt exists. `measure()` reports accuracy without granting a receipt, so you can learn that a detector detects nothing without being allowed to publish its counts.
**Catches:** a classifier or join that fires on everything (tuned on positives only, its over-admission is invisible).

```python
cases = [tw.Case("row 812", "Pay per article, $0.01", True), ...,       # >= 5 known-true, from real rows
         tw.Case("row 77", "ETH gas price lookup", False), ...]         # >= 5 known-false
tw.calibrate("content detector", cases, is_content, bar=0.9)
n = tw.count(sum(map(is_content, listings)), "content listings")       # allowed: a receipt exists
tw.stamp()   # '... | calibrated: content detector 92% on 12 (6T/6F, bar 90%)'
```

## 5. Shuffled-label control: `shuffled_control`
**What:** scores a judge or matcher against the true labels and against random permutations of them, and reports the chance floor, the lift over it and a permutation p-value.
**Catches:** a lenient judge whose high agreement comes from the label mix, not from the cases. A judge that says "yes" to everything scores 90% when 90% of labels are yes, and so does every shuffle.

```python
r = tw.shuffled_control(judge_verdicts, gold_labels, n=1000)
r["real"], r["shuffled_mean"], r["p_value"]   # e.g. (0.90, 0.90, 1.0): agreement is all floor, no signal
```

## 6. Pre-registration guard: `prereg`
**What:** keeps a ledger of a pre-registration file's hashes; `check()` aborts the analysis if the file's current hash was never registered, so every edit after registration must be logged with a note (a deviation, an addendum).
**Catches:** hypotheses or bars edited after the results were seen, silently.

```python
from tripwire_checks import prereg
prereg.register("PREREG.md", "PREREG_HASHES.txt", note="v1, before any data")
prereg.check("PREREG.md", "PREREG_HASHES.txt")   # first line of the analysis; aborts on an unlogged edit
```
CLI: `tripwire prereg check PREREG.md PREREG_HASHES.txt`

## Tests
`pytest -q`. Every check is tested in both directions, including its own negative control: the vacuous check is caught, the masked exit is caught, the lenient judge is caught, the edited pre-registration is caught.

## Origin
Ported and simplified from the checking tools in my research workflow (see the papers at https://wknipe.com). Each check exists because its failure happened in practice.
