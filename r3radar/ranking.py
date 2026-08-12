from __future__ import annotations

from typing import Any


SCORE_KEYS = (
    "novelty",
    "r3_relevance",
    "evidence_strength",
    "reuse_signal_value",
    "implementability",
)


class AmbiguousScoreScaleError(ValueError):
    pass


def normalize_and_rank(analysis: dict[str, Any]) -> tuple[float, str, bool]:
    scores = analysis["scores"]
    raw = {key: float(scores[key]) for key in (*SCORE_KEYS, "overall")}
    declared = analysis.get("score_scale")
    if declared is None:
        declared = (analysis.get("score_normalization") or {}).get(
            "declared_input_scale"
        )
    if declared == "0_to_10":
        multiplier = 10.0
    elif declared == "0_to_100":
        multiplier = 1.0
    else:
        raise AmbiguousScoreScaleError(
            "score_scale must explicitly be 0_to_10 or 0_to_100"
        )
    normalized = {
        key: round(min(100.0, max(0.0, raw[key] * multiplier)), 2)
        for key in SCORE_KEYS
    }
    overall = round(
        0.15 * normalized["novelty"]
        + 0.25 * normalized["r3_relevance"]
        + 0.15 * normalized["evidence_strength"]
        + 0.25 * normalized["reuse_signal_value"]
        + 0.20 * normalized["implementability"],
        2,
    )
    normalized["overall"] = overall
    if normalized["r3_relevance"] < 35:
        tier = "out_of_scope_after_deep_read"
    elif overall >= 85 and normalized["r3_relevance"] >= 80:
        tier = "must_read"
    elif overall >= 68:
        tier = "important"
    else:
        tier = "background"
    changed = scores != normalized or analysis.get("tier") != tier
    analysis["scores"] = normalized
    analysis["tier"] = tier
    analysis["score_normalization"] = {
        "declared_input_scale": declared,
        "multiplier": multiplier,
        "raw_scores": raw,
        "deterministic_formula": (
            "0.15*novelty + 0.25*r3_relevance + 0.15*evidence_strength + "
            "0.25*reuse_signal_value + 0.20*implementability"
        ),
    }
    analysis["score_scale"] = "0_to_100"
    return overall, tier, changed
