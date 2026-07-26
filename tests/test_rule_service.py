"""Tests for the rule service."""

from app.services.rule_service import RuleService


def test_get_all_returns_supported_detection_rules() -> None:
    service = RuleService()

    rules = service.get_all()

    assert len(rules) == 11
    assert rules[0] == {
        "id": "deauthentication_flood",
        "name": "Deauthentication Flood",
        "enabled": True,
    }


def test_get_all_returns_a_separate_collection() -> None:
    service = RuleService()

    first_result = service.get_all()
    first_result[0]["enabled"] = False

    second_result = service.get_all()

    assert second_result[0]["enabled"] is True
