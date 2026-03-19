"""
Security Scorer - Calculates overall security posture.

This module provides comprehensive security scoring for Docker environments
based on detected risks and attack path analysis. It generates a 0-100 score
with letter grades (A-F) and detailed assessment reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from dockerscope.models.risk import Risk

# Risk type severity penalties
SEVERITY_PENALTIES = {
    "docker_sock_mount": 30,  # CRITICAL
    "privileged_container": 30,  # CRITICAL
    "critical_capability": 30,  # CRITICAL
    "dangerous_host_mount": 20,  # HIGH
    "host_network_mode": 15,  # HIGH
    "host_pid_mode": 15,  # HIGH
    "dangerous_capability": 12,  # HIGH
    "wide_exposed_port": 7,  # MEDIUM
    "no_security_profiles": 7,  # MEDIUM
    "no_resource_limits": 5,  # MEDIUM
    "running_as_root": 3,  # LOW
    "unpinned_image": 3,  # LOW
}


@dataclass
class SecurityScore:
    """
    Comprehensive security score for Docker environment.

    Attributes:
        total_score: Final score (0-100)
        base_score: Score before attack path adjustments
        risk_counts: Count of each risk type detected
        attack_path_penalty: Additional penalty for attack paths
        direct_host_paths: Number of direct paths to host
        grade: Letter grade (A-F)
        assessment: Human-readable assessment
    """
    total_score: int
    base_score: int
    risk_counts: dict[str, int]
    attack_path_penalty: int
    direct_host_paths: int
    grade: str
    assessment: str


def calculate_security_score(
        risks: Iterable[Risk],
        attack_paths: Optional[list] = None
) -> SecurityScore:
    """
    Calculate comprehensive security score for environment.

    Scoring process:
    1. Start with 100 points
    2. Deduct points for each risk (based on severity)
    3. Apply additional penalty for direct attack paths
    4. Calculate letter grade
    5. Generate assessment text

    Args:
        risks: List of detected security risks
        attack_paths: List of attack paths (optional)

    Returns:
        SecurityScore object with complete analysis
    """
    # Count risks by type
    risk_counts = _count_risks_by_type(risks)

    # Calculate base score from risks
    base_score = _calculate_base_score(risk_counts)

    # Analyze attack paths for additional penalties
    attack_path_penalty, direct_paths = _calculate_attack_path_penalty(
        attack_paths or []
    )

    # Final score (minimum 0)
    total_score = max(0, base_score - attack_path_penalty)

    # Calculate letter grade and assessment
    grade = _calculate_grade(total_score)
    assessment = _generate_assessment(total_score, risk_counts, direct_paths)

    return SecurityScore(
        total_score=total_score,
        base_score=base_score,
        risk_counts=risk_counts,
        attack_path_penalty=attack_path_penalty,
        direct_host_paths=direct_paths,
        grade=grade,
        assessment=assessment
    )


def _count_risks_by_type(risks: Iterable[Risk]) -> dict[str, int]:
    """
    Count occurrences of each risk type.

    Returns:
        Dictionary mapping risk_type -> count
    """
    counts: dict[str, int] = {}

    for risk in risks:
        risk_type = risk.risk_type
        counts[risk_type] = counts.get(risk_type, 0) + 1

    return counts


def _calculate_base_score(risk_counts: dict[str, int]) -> int:
    """
    Calculate base score from risk counts.

    Formula:
        score = 100 - (sum of penalties for all risks)

    Args:
        risk_counts: Dictionary of risk_type -> count

    Returns:
        Score between 0 and 100
    """
    score = 100

    # Deduct points for each risk
    for risk_type, count in risk_counts.items():
        penalty = SEVERITY_PENALTIES.get(risk_type, 5)  # Default 5 if unknown
        score -= (count * penalty)

    return max(0, score)


def _calculate_attack_path_penalty(attack_paths: list) -> tuple[int, int]:
    """
    Calculate additional penalty based on attack paths.

    Direct paths (1-2 hops) to host receive higher penalties
    than longer, indirect paths.

    Args:
        attack_paths: List of AttackPath objects

    Returns:
        Tuple of (total_penalty, direct_paths_count)
    """
    if not attack_paths:
        return 0, 0

    direct_paths = 0
    penalty = 0

    for path in attack_paths:
        path_length = len(path.nodes) - 1  # Number of hops

        # Direct path (1-2 hops) = high penalty
        if path_length <= 2:
            direct_paths += 1
            penalty += 20
        # Medium path (3-4 hops) = medium penalty
        elif path_length <= 4:
            penalty += 10
        # Long path (5+ hops) = low penalty
        else:
            penalty += 5

    return penalty, direct_paths


def _calculate_grade(score: int) -> str:
    """
    Calculate letter grade from numeric score.

    Grading scale:
        90-100: A (Excellent)
        80-89:  B (Good)
        70-79:  C (Fair)
        60-69:  D (Poor)
        0-59:   F (Critical)

    Args:
        score: Numeric score (0-100)

    Returns:
        Letter grade (A-F)
    """
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


def _generate_assessment(
        score: int,
        risk_counts: dict[str, int],
        direct_paths: int
) -> str:
    """
    Generate human-readable security assessment.

    Args:
        score: Numeric score
        risk_counts: Risk type counts
        direct_paths: Number of direct host access paths

    Returns:
        Assessment string
    """
    if score >= 90:
        return "Excellent security posture. Keep up the good work!"
    elif score >= 80:
        return "Good security posture with minor issues to address."
    elif score >= 70:
        return "Moderate security posture. Review and address identified risks."
    elif score >= 60:
        return "Poor security posture. Take action to improve configuration."
    else:
        # Critical - check for direct paths
        if direct_paths > 0:
            return (
                f"CRITICAL security posture! {direct_paths} direct path(s) "
                "to host compromise detected. Urgent action required!"
            )
        return "CRITICAL security posture. Immediate remediation required!"


def generate_score_report(score: SecurityScore) -> str:
    """
    Generate detailed text report of security score.

    Includes:
    - Overall score and grade
    - Risk breakdown by type
    - Score calculation details
    - Assessment and recommendations

    Args:
        score: SecurityScore object

    Returns:
        Formatted text report
    """
    lines = []

    lines.append("=" * 60)
    lines.append("DOCKER ENVIRONMENT SECURITY SCORE")
    lines.append("=" * 60)
    lines.append("")

    # Overall score
    lines.append(f"Overall Score: {score.total_score}/100 (Grade: {score.grade})")
    lines.append("")

    # Risk breakdown
    if score.risk_counts:
        lines.append("Risk Breakdown:")

        # Sort by severity (most severe first)
        severity_order = [
            "docker_sock_mount",
            "privileged_container",
            "critical_capability",
            "dangerous_host_mount",
            "host_network_mode",
            "host_pid_mode",
            "dangerous_capability",
            "wide_exposed_port",
            "no_security_profiles",
            "no_resource_limits",
            "running_as_root",
            "unpinned_image"
        ]

        # Display known types in severity order
        for risk_type in severity_order:
            count = score.risk_counts.get(risk_type, 0)
            if count > 0:
                lines.append(f"  {risk_type}: {count}")

        # Display any unknown types
        for risk_type, count in score.risk_counts.items():
            if risk_type not in severity_order:
                lines.append(f"  {risk_type}: {count}")

        total_risks = sum(score.risk_counts.values())
        lines.append(f"  Total: {total_risks}")
        lines.append("")

    # Score calculation breakdown
    if score.base_score != score.total_score:
        lines.append("Score Calculation:")
        lines.append(f"  Base score (from risks): {score.base_score}/100")
        if score.attack_path_penalty > 0:
            lines.append(f"  Attack path penalty: -{score.attack_path_penalty}")
            if score.direct_host_paths > 0:
                lines.append(f"    ({score.direct_host_paths} direct host access path(s))")
        lines.append(f"  Final score: {score.total_score}/100")
        lines.append("")

    # Assessment
    lines.append("Assessment:")
    lines.append(f"  {score.assessment}")
    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)


def get_severity_level(risk_type: str) -> str:
    """
    Get severity level for a risk type.

    Args:
        risk_type: Risk type identifier

    Returns:
        "CRITICAL", "HIGH", "MEDIUM", or "LOW"
    """
    penalty = SEVERITY_PENALTIES.get(risk_type, 0)

    if penalty >= 25:
        return "CRITICAL"
    elif penalty >= 12:
        return "HIGH"
    elif penalty >= 5:
        return "MEDIUM"
    else:
        return "LOW"
