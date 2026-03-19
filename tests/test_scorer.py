"""Tests for security scoring."""
from __future__ import annotations

from dockerscope.models.risk import Risk
from dockerscope.attack.attack_graph import AttackPath
from dockerscope.core.scorer import (
    SecurityScore,
    calculate_security_score,
    generate_score_report,
    _calculate_grade,
    _count_risks_by_type,
)


def _risk(risk_type: str, container: str = "c") -> Risk:
    return Risk(container=container, risk_type=risk_type, description="", details={})


class TestCalculateSecurityScore:
    def test_no_risks_perfect_score(self):
        score = calculate_security_score([])
        assert score.total_score == 100
        assert score.grade == "A"

    def test_single_critical_risk(self):
        score = calculate_security_score([_risk("docker_sock_mount")])
        assert score.total_score == 70  # 100 - 30
        assert score.grade == "C"

    def test_multiple_risks_deducted(self):
        risks = [_risk("docker_sock_mount"), _risk("privileged_container")]
        score = calculate_security_score(risks)
        assert score.total_score == 40  # 100 - 30 - 30

    def test_score_does_not_go_below_zero(self):
        risks = [_risk("docker_sock_mount")] * 5  # 5 * 30 = 150, but min is 0
        score = calculate_security_score(risks)
        assert score.total_score == 0
        assert score.grade == "F"

    def test_attack_path_penalty(self):
        risks = [_risk("wide_exposed_port")]  # 7 point penalty = 93 base
        path = AttackPath(
            path_id="x",
            nodes=["web", "host_root"],  # 1 hop = direct path, +20 penalty
            description="",
        )
        score = calculate_security_score(risks, attack_paths=[path])
        assert score.total_score == 73  # 93 - 20
        assert score.attack_path_penalty == 20
        assert score.direct_host_paths == 1

    def test_long_path_lower_penalty(self):
        path = AttackPath(
            path_id="x",
            nodes=["a", "b", "c", "d", "e", "f"],  # 5 hops = long path, +5
            description="",
        )
        score = calculate_security_score([], attack_paths=[path])
        assert score.attack_path_penalty == 5


class TestCalculateGrade:
    def test_grade_a(self):
        assert _calculate_grade(90) == "A"
        assert _calculate_grade(100) == "A"

    def test_grade_b(self):
        assert _calculate_grade(80) == "B"
        assert _calculate_grade(89) == "B"

    def test_grade_c(self):
        assert _calculate_grade(70) == "C"

    def test_grade_d(self):
        assert _calculate_grade(60) == "D"

    def test_grade_f(self):
        assert _calculate_grade(59) == "F"
        assert _calculate_grade(0) == "F"


class TestCountRisksByType:
    def test_empty(self):
        assert _count_risks_by_type([]) == {}

    def test_counts(self):
        risks = [
            _risk("docker_sock_mount"),
            _risk("docker_sock_mount"),
            _risk("privileged_container"),
        ]
        counts = _count_risks_by_type(risks)
        assert counts["docker_sock_mount"] == 2
        assert counts["privileged_container"] == 1


class TestScoreReport:
    def test_report_contains_score(self):
        score = calculate_security_score([])
        report = generate_score_report(score)
        assert "100/100" in report
        assert "Grade: A" in report

    def test_report_contains_risk_breakdown(self):
        score = calculate_security_score([_risk("docker_sock_mount")])
        report = generate_score_report(score)
        assert "docker_sock_mount" in report

    def test_report_contains_assessment(self):
        score = calculate_security_score([])
        report = generate_score_report(score)
        assert "Assessment" in report
