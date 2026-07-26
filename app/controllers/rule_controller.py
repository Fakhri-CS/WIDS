"""HTTP endpoints for WIDS detection rules."""

from http import HTTPStatus

from flask import Blueprint, jsonify

from app.services.rule_service import RuleService


rule_controller = Blueprint(
    "rule_controller",
    __name__,
    url_prefix="/api/v1/rules",
)

rule_service = RuleService()


@rule_controller.get("")
def get_rules():
    """Return all supported WIDS detection rules."""
    rules = rule_service.get_all()

    return jsonify(
        {
            "rules": rules,
            "count": len(rules),
        }
    ), HTTPStatus.OK
