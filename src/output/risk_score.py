"""
Risk Scoring System
Computes a normalized security score (0-100) and letter grade for a contract,
factoring in finding severity, count, confidence, and compound risk multipliers.
"""
from typing import List, Dict, Any
from dataclasses import dataclass

from ..rules.rule_engine import Finding, Severity


# Severity base weights (out of 100 points per finding)
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
}

# Tags that compound risk when multiple findings share them
COMPOUND_TAGS = {
    frozenset({"access-control", "state-mutation"}): 1.4,
    frozenset({"capability", "enforce"}): 1.3,
    frozenset({"cei", "reentrancy"}): 1.5,
    frozenset({"admin", "access-control"}): 1.35,
    frozenset({"managed-capability", "double-spend"}): 1.45,
}


@dataclass
class RiskScore:
    raw_score: float       # 0–100, higher = riskier
    normalized: float      # 0–100, higher = safer (inverted)
    letter_grade: str      # A+ through F
    label: str             # "Low Risk", "High Risk", etc.
    breakdown: Dict[str, Any]
    compound_multiplier: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_score": round(self.raw_score, 2),
            "security_score": round(self.normalized, 2),
            "letter_grade": self.letter_grade,
            "label": self.label,
            "compound_multiplier": round(self.compound_multiplier, 3),
            "breakdown": self.breakdown,
        }


def compute_risk_score(findings: List[Finding]) -> RiskScore:
    """Compute a holistic risk score from a list of findings."""
    if not findings:
        return RiskScore(
            raw_score=0, normalized=100,
            letter_grade="A+", label="Clean",
            breakdown={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            compound_multiplier=1.0,
        )

    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings)}

    base_score = 0.0
    for f in findings:
        weight = SEVERITY_WEIGHTS[f.severity]
        adjusted = weight * f.confidence
        base_score += adjusted
        breakdown[f.severity.value] += 1

    # Apply compound multiplier
    multiplier = _compute_compound_multiplier(findings)
    raw_score = min(base_score * multiplier, 200)  # cap at 200

    # Normalize to 0-100 risk scale
    # 200 raw = totally broken (0 safe score)
    # 0 raw = perfect (100 safe score)
    safe_score = max(0.0, 100.0 - (raw_score / 2.0))

    grade, label = _grade(safe_score)

    return RiskScore(
        raw_score=raw_score,
        normalized=safe_score,
        letter_grade=grade,
        label=label,
        breakdown=breakdown,
        compound_multiplier=multiplier,
    )


def _compute_compound_multiplier(findings: List[Finding]) -> float:
    all_tags = set()
    for f in findings:
        all_tags.update(f.tags)

    multiplier = 1.0
    for tag_set, factor in COMPOUND_TAGS.items():
        if tag_set.issubset(all_tags):
            multiplier = max(multiplier, factor)
    return multiplier


def _grade(safe_score: float) -> tuple:
    if safe_score >= 97:
        return "A+", "Excellent"
    elif safe_score >= 90:
        return "A", "Very Good"
    elif safe_score >= 80:
        return "B", "Good"
    elif safe_score >= 70:
        return "C", "Moderate Risk"
    elif safe_score >= 55:
        return "D", "High Risk"
    elif safe_score >= 35:
        return "F", "Critical Risk"
    else:
        return "F-", "Severely Vulnerable"
