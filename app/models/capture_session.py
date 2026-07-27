"""Database model for packet-capture sessions."""

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db


def utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""
    return datetime.now(timezone.utc)


class CaptureSession(db.Model):  # type: ignore[name-defined]
    """Represent one packet-capture session."""

    __tablename__ = "capture_sessions"

    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'stopped', 'failed')",
            name="ck_capture_sessions_status",
        ),
        CheckConstraint(
            "packet_count >= 0",
            name="ck_capture_sessions_packet_count_nonnegative",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    interface: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(16),
        default="running",
        server_default="running",
        nullable=False,
        index=True,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    stopped_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    packet_count: Mapped[int] = mapped_column(
        BigInteger,
        default=0,
        server_default="0",
        nullable=False,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
