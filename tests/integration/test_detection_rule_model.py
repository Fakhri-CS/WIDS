from sqlalchemy import select

from wids import create_app
from wids.config import TestingConfig
from wids.extensions import db
from wids.models import DetectionRule


def test_detection_rule_can_be_persisted() -> None:
    app = create_app(TestingConfig)

    with app.app_context():
        db.create_all()

        try:
            rule = DetectionRule(
                code="WIDS-R001",
                name="Deauthentication Flood",
                description=(
                    "Detects excessive deauthentication frames within a configured time window."
                ),
                enabled=True,
                default_severity="high",
                parameters={
                    "threshold": 20,
                    "window_seconds": 10,
                    "cooldown_seconds": 30,
                },
                rule_version=1,
            )

            db.session.add(rule)
            db.session.commit()

            stored_rule = db.session.scalar(
                select(DetectionRule).where(DetectionRule.code == "WIDS-R001")
            )

            assert stored_rule is not None
            assert stored_rule.name == "Deauthentication Flood"
            assert stored_rule.enabled is True
            assert stored_rule.parameters["threshold"] == 20

        finally:
            db.session.remove()
            db.drop_all()
