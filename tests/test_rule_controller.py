"""Tests for the rule controller."""

from http import HTTPStatus

from flask.testing import FlaskClient


def test_get_rules_returns_detection_rule_collection(
    client: FlaskClient,
) -> None:
    response = client.get("/api/v1/rules")

    assert response.status_code == HTTPStatus.OK
    assert response.content_type == "application/json"

    body = response.get_json()

    assert body["count"] == 11
    assert len(body["rules"]) == 11

    assert body["rules"][0] == {
        "id": "deauthentication_flood",
        "name": "Deauthentication Flood",
        "enabled": True,
    }
