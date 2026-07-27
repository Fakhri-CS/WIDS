"""Application service for packet capture operations."""

from sqlalchemy import select

from app.extensions import db
from app.models import CaptureSession
from app.models.capture_session import utc_now


class CaptureService:
    """Manage packet-capture session state in the database."""

    @staticmethod
    def _get_running_session() -> CaptureSession | None:
        """Return the most recent running capture session."""
        statement = (
            select(CaptureSession)
            .where(CaptureSession.status == "running")
            .order_by(
                CaptureSession.started_at.desc(),
                CaptureSession.id.desc(),
            )
            .limit(1)
        )

        return db.session.scalar(statement)

    def start(self, interface: str) -> dict[str, str] | None:
        """Create a running capture session.

        Return None when capture is already running.
        """
        if self._get_running_session() is not None:
            return None

        capture_session = CaptureSession(
            interface=interface,
            status="running",
        )

        db.session.add(capture_session)
        db.session.commit()

        return {
            "status": capture_session.status,
            "interface": capture_session.interface,
        }

    def stop(self) -> dict[str, str] | None:
        """Stop the current capture session.

        Return None when no capture session is running.
        """
        capture_session = self._get_running_session()

        if capture_session is None:
            return None

        capture_session.status = "stopped"
        capture_session.stopped_at = utc_now()

        db.session.commit()

        return {
            "status": capture_session.status,
            "interface": capture_session.interface,
        }

    def get_status(self) -> dict[str, str | None]:
        """Return the persisted packet-capture status."""
        capture_session = self._get_running_session()

        if capture_session is None:
            return {
                "status": "stopped",
                "interface": None,
            }

        return {
            "status": capture_session.status,
            "interface": capture_session.interface,
        }
