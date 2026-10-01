"""Shuffled-label control: how often would this judge or matcher agree with labels by chance?"""
from __future__ import annotations

import random
from typing import Callable, Sequence


def shuffled_control(predictions: Sequence, labels: Sequence, *, score: Callable | None = None,
                     n: int = 1000, seed: int = 0) -> dict:
    """Score predictions against the true labels and against `n` random permutations of them.

    Returns the real score, the shuffled floor (mean, 95th percentile) and the share of shuffles
    scoring at least as well as the real labels (a permutation p-value). A judge whose real score
    sits near its shuffled floor is agreeing with the label distribution, not with the cases.
    `score(preds, labels) -> float` defaults to exact agreement."""
    if len(predictions) != len(labels) or not labels:
        raise ValueError("predictions and labels must be the same non-zero length")
    score = score or (lambda p, l: sum(a == b for a, b in zip(p, l)) / len(l))
    real = score(predictions, labels)
    rng = random.Random(seed)
    lab = list(labels)
    floor = []
    for _ in range(n):
        rng.shuffle(lab)
        floor.append(score(predictions, lab))
    floor.sort()
    return dict(real=real, shuffled_mean=sum(floor) / n, shuffled_p95=floor[int(0.95 * (n - 1))],
                p_value=(1 + sum(f >= real for f in floor)) / (n + 1), n=n,
                lift=real - sum(floor) / n)
