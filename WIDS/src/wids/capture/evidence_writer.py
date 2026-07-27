"""Runtime PCAP evidence path allocation and safe file persistence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
from threading import Lock
from uuid import UUID

from wids.capture.frame_models import ensure_utc


class EvidenceWriterError(RuntimeError):
    """Raised when runtime evidence cannot be safely persisted."""


@dataclass(frozen=True, slots=True)
class EvidenceTarget:
    """Internal output path paired with its external opaque reference."""

    storage_path: Path
    pcap_reference: str
    capture_session_id: UUID
    created_at: datetime


@dataclass(frozen=True, slots=True)
class EvidenceMetadata:
    """Metadata calculated after a PCAP file is closed."""

    pcap_reference: str
    size_bytes: int
    file_sha256: str


class EvidenceWriter:
    """Allocate and manage files beneath the configured runtime PCAP root.

    PyShark/TShark writes the live PCAP bytes to ``EvidenceTarget.storage_path``.
    This class owns safe naming, storage-relative references, replay copies, and
    final integrity metadata; it does not attempt to implement the PCAP format.
    """

    def __init__(
        self,
        root_directory: str | Path,
        *,
        reference_prefix: str = "runtime/pcap",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.root_directory = Path(root_directory).expanduser()
        self.reference_prefix = _normalize_reference(reference_prefix)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = Lock()

    def prepare_live_capture(
        self,
        capture_session_id: UUID,
        *,
        extension: str = ".pcapng",
    ) -> EvidenceTarget:
        """Reserve a unique output name for one live capture session."""

        extension = _validate_extension(extension)
        created_at = ensure_utc(self._clock())
        timestamp = created_at.strftime("%Y%m%dT%H%M%S%fZ")
        base_name = f"{capture_session_id}_{timestamp}"
        with self._lock:
            self.root_directory.mkdir(parents=True, exist_ok=True)
            path = self.root_directory / f"{base_name}{extension}"
            counter = 1
            while path.exists():
                path = self.root_directory / (
                    f"{base_name}_{counter}{extension}"
                )
                counter += 1
        return EvidenceTarget(
            storage_path=path,
            pcap_reference=f"{self.reference_prefix}/{path.name}",
            capture_session_id=capture_session_id,
            created_at=created_at,
        )

    def copy_replay_evidence(
        self,
        source: str | Path,
        capture_session_id: UUID,
    ) -> EvidenceTarget:
        """Atomically copy a replay PCAP into runtime evidence storage."""

        source_path = Path(source).expanduser()
        if not source_path.is_file():
            raise FileNotFoundError(f"Replay PCAP does not exist: {source_path}")
        extension = _validate_extension(source_path.suffix or ".pcap")
        target = self.prepare_live_capture(
            capture_session_id,
            extension=extension,
        )
        temporary = target.storage_path.with_suffix(
            f"{target.storage_path.suffix}.part"
        )
        try:
            shutil.copyfile(source_path, temporary)
            os.replace(temporary, target.storage_path)
        except OSError as error:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise EvidenceWriterError(
                f"Unable to copy replay evidence: {error}"
            ) from error
        return target

    def finalize(self, target: EvidenceTarget) -> EvidenceMetadata:
        """Verify a completed evidence file and calculate its SHA-256 digest."""

        self._assert_owned_path(target.storage_path)
        if not target.storage_path.is_file():
            raise EvidenceWriterError(
                f"Evidence file was not created: {target.pcap_reference}"
            )
        digest = hashlib.sha256()
        try:
            with target.storage_path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            size = target.storage_path.stat().st_size
        except OSError as error:
            raise EvidenceWriterError(
                f"Unable to finalize evidence: {error}"
            ) from error
        return EvidenceMetadata(
            pcap_reference=target.pcap_reference,
            size_bytes=size,
            file_sha256=digest.hexdigest(),
        )

    def reference_for_fixture(
        self,
        path: str | Path,
        *,
        fixture_root: str | Path = "pcap_samples",
    ) -> str:
        """Return a stable fixture reference without exposing an absolute path."""

        fixture = Path(path)
        root = Path(fixture_root)
        try:
            relative = fixture.resolve().relative_to(root.resolve())
        except ValueError:
            relative = Path(fixture.name)
        return _normalize_reference(f"{root.name}/{relative.as_posix()}")

    def _assert_owned_path(self, path: Path) -> None:
        try:
            path.resolve().relative_to(self.root_directory.resolve())
        except ValueError as error:
            raise EvidenceWriterError(
                "Evidence path is outside the configured runtime directory"
            ) from error


def _validate_extension(extension: str) -> str:
    normalized = extension.lower()
    if not normalized.startswith("."):
        normalized = f".{normalized}"
    if normalized not in {".pcap", ".pcapng", ".cap"}:
        raise ValueError("Evidence extension must be .pcap, .pcapng, or .cap")
    return normalized


def _normalize_reference(reference: str) -> str:
    normalized = str(reference).strip().replace("\\", "/").strip("/")
    if not normalized:
        raise ValueError("Evidence reference cannot be empty")
    if any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise ValueError("Evidence reference contains an unsafe path component")
    return normalized
