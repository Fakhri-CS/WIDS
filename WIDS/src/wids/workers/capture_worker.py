"""Independent capture-and-detection worker entry point."""

from __future__ import annotations

import argparse
import json
import logging
import signal
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import cast
from uuid import uuid4

from wids.capture.capture_manager import (
    CaptureManager,
    FeatureSink,
    FrameSink,
)
from wids.capture.channel_manager import (
    ChannelHopper,
    ChannelManager,
    ChannelPlan,
)
from wids.capture.evidence_writer import (
    EvidenceMetadata,
    EvidenceTarget,
    EvidenceWriter,
)
from wids.capture.feature_extractor import (
    FeatureExtractor,
    FeatureUpdate,
)
from wids.capture.frame_models import (
    CaptureSource,
    CaptureStatus,
    NormalizedWirelessFrame,
)
from wids.capture.interface_manager import (
    CommandRunner,
    InterfaceManager,
)
from wids.capture.packet_parser import PacketParser
from wids.capture.packet_source import (
    CaptureFactory,
    LivePacketSource,
    PacketSource,
    PcapPacketSource,
)
from wids.contracts.detection_event import DetectionEvent
from wids.detection.bootstrap import (
    build_detection_engine_from_yaml,
)
from wids.detection.runtime import (
    DetectionEngineRuntime,
    DetectionEventSink,
    DetectionFeatureSink,
)
from wids.workers.heartbeat import (
    HeartbeatPublisher,
    HeartbeatService,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    """All capture and detection worker settings."""

    source_mode: CaptureSource
    feature_window_seconds: tuple[float, ...]
    runtime_pcap_directory: Path
    heartbeat_interval_seconds: float

    worker_id: str = "capture-worker"

    interface_name: str | None = None

    pcap_path: Path | None = None
    pcap_reference: str | None = None

    channels: tuple[int, ...] = ()
    channel_dwell_seconds: float = 1.0
    channel_width: str | None = None

    ensure_monitor_mode: bool = True

    display_filter: str | None = None
    bpf_filter: str | None = None

    detection_config_path: Path | None = None

    def __post_init__(self) -> None:
        if not self.feature_window_seconds:
            raise ValueError("feature_window_seconds cannot be empty")

        if self.heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat_interval_seconds must be positive")

        if not self.worker_id.strip():
            raise ValueError("worker_id is required")

        if self.source_mode is CaptureSource.LIVE:
            if not self.interface_name:
                raise ValueError("interface_name is required for live capture")

            if self.pcap_path is not None:
                raise ValueError("pcap_path is not valid for live capture")

        else:
            if self.pcap_path is None:
                raise ValueError("pcap_path is required for PCAP replay")

            if self.interface_name is not None:
                raise ValueError("interface_name is not valid for PCAP replay")

            if self.channels:
                raise ValueError("channels are not valid for PCAP replay")

        if self.channels and self.channel_dwell_seconds <= 0:
            raise ValueError("channel_dwell_seconds must be positive")


class _CompositeFeatureSink:
    """Invoke multiple feature sinks for the same parsed frame."""

    def __init__(
        self,
        sinks: tuple[FeatureSink, ...],
    ) -> None:
        if len(sinks) < 2:
            raise ValueError("Composite sink requires at least two sinks")

        self._sinks = sinks

    def __call__(
        self,
        frame: NormalizedWirelessFrame,
        update: FeatureUpdate,
    ) -> None:
        """Invoke all sinks and propagate the first failure."""

        first_error: Exception | None = None

        for sink in self._sinks:
            try:
                sink(frame, update)
            except Exception as error:
                if first_error is None:
                    first_error = error

        if first_error is not None:
            raise first_error


def _combine_feature_sinks(
    *sinks: FeatureSink | None,
) -> FeatureSink | None:
    """Return zero, one, or a composite feature sink."""

    active_sinks = tuple(sink for sink in sinks if sink is not None)

    if not active_sinks:
        return None

    if len(active_sinks) == 1:
        return active_sinks[0]

    return _CompositeFeatureSink(active_sinks)


class CaptureWorker:
    """Own capture, parsing, detection, evidence, and heartbeat."""

    def __init__(
        self,
        config: WorkerConfig,
        *,
        frame_sink: FrameSink | None = None,
        feature_sink: FeatureSink | None = None,
        detection_event_sink: (DetectionEventSink | None) = None,
        heartbeat_publisher: (HeartbeatPublisher | None) = None,
        command_runner: CommandRunner | None = None,
        file_capture_factory: (CaptureFactory | None) = None,
        live_capture_factory: (CaptureFactory | None) = None,
    ) -> None:
        self.config = config

        self._parser = PacketParser()

        self._features = FeatureExtractor(config.feature_window_seconds)

        self._detection_feature_sink: DetectionFeatureSink | None = None

        detection_runtime_sink: FeatureSink | None = None

        if config.detection_config_path is not None:
            detection_engine = cast(
                DetectionEngineRuntime,
                build_detection_engine_from_yaml(config.detection_config_path),
            )

            self._detection_feature_sink = DetectionFeatureSink(
                detection_engine,
                detection_event_sink or _log_detection_event,
            )

            detection_runtime_sink = self._detection_feature_sink

        elif detection_event_sink is not None:
            raise ValueError("detection_event_sink requires detection_config_path")

        manager_feature_sink = _combine_feature_sinks(
            feature_sink,
            detection_runtime_sink,
        )

        self._manager = CaptureManager(
            self._parser,
            self._features,
            frame_sink=frame_sink,
            feature_sink=manager_feature_sink,
            on_processing_error=(self._on_processing_error),
        )

        self._heartbeat_publisher = heartbeat_publisher or _discard_heartbeat

        self._command_runner = command_runner

        self._file_capture_factory = file_capture_factory

        self._live_capture_factory = live_capture_factory

        self._heartbeat: HeartbeatService | None = None
        self._hopper: ChannelHopper | None = None

        self._evidence_target: EvidenceTarget | None = None

        self._evidence_writer: EvidenceWriter | None = None

        self._last_evidence_metadata: EvidenceMetadata | None = None

        self._background_error: Exception | None = None

        self._lock = Lock()

    def run(self) -> CaptureStatus:
        """Build the configured source and run it."""

        source = self._build_source()

        return self.run_source(source)

    def run_source(
        self,
        source: PacketSource,
    ) -> CaptureStatus:
        """Run an injected live, replay, or test source."""

        capture_session_id = source.capture_session_id

        with self._lock:
            self._background_error = None

        self._last_evidence_metadata = None

        heartbeat = HeartbeatService(
            worker_id=self.config.worker_id,
            interval_seconds=(self.config.heartbeat_interval_seconds),
            status_provider=(self._manager.touch_heartbeat),
            publisher=(self._heartbeat_publisher),
            on_error=self._on_heartbeat_error,
        )

        self._heartbeat = heartbeat

        heartbeat.start()

        if self._hopper is not None:
            self._hopper.start()

        try:
            status = self._manager.run(source)

            with self._lock:
                background_error = self._background_error

            if background_error is not None:
                raise RuntimeError(
                    f"Background worker operation failed: {background_error}"
                ) from background_error

            return status

        finally:
            if self._hopper is not None:
                self._hopper.stop(timeout=5.0)

            heartbeat.stop(
                timeout=5.0,
                publish_final=True,
            )

            self._finalize_evidence()

            if self._detection_feature_sink is not None:
                self._detection_feature_sink.reset_session(capture_session_id)

    def stop(self) -> None:
        """Request an orderly worker shutdown."""

        self._manager.stop()

        if self._hopper is not None:
            self._hopper.stop(timeout=5.0)

    def status(self) -> CaptureStatus:
        """Return the latest capture status."""

        return self._manager.status()

    @property
    def last_evidence_metadata(
        self,
    ) -> EvidenceMetadata | None:
        """Return finalized live-capture evidence metadata."""

        return self._last_evidence_metadata

    def _build_source(self) -> PacketSource:
        if self.config.source_mode is CaptureSource.PCAP:
            assert self.config.pcap_path is not None

            return PcapPacketSource(
                self.config.pcap_path,
                pcap_reference=(self.config.pcap_reference),
                display_filter=(self.config.display_filter),
                capture_factory=(self._file_capture_factory),
            )

        assert self.config.interface_name is not None

        interface_manager = InterfaceManager(self._command_runner)

        if self.config.ensure_monitor_mode:
            interface_manager.ensure_monitor_mode(self.config.interface_name)

        evidence_writer = EvidenceWriter(self.config.runtime_pcap_directory)

        target = evidence_writer.prepare_live_capture(
            self._manager.status().capture_session_id or uuid4()
        )

        self._evidence_target = target
        self._evidence_writer = evidence_writer

        if self.config.channels:
            channel_manager = ChannelManager(
                self.config.interface_name,
                self._command_runner,
            )

            plan = ChannelPlan(
                channels=self.config.channels,
                dwell_seconds=(self.config.channel_dwell_seconds),
                width=self.config.channel_width,
            )

            if len(plan.channels) == 1:
                channel_manager.set_channel(
                    plan.channels[0],
                    plan.width,
                )

                self._manager.update_current_channel(plan.channels[0])

            else:
                channel_manager.set_channel(
                    plan.channels[0],
                    plan.width,
                )

                self._manager.update_current_channel(plan.channels[0])

                self._hopper = ChannelHopper(
                    channel_manager,
                    plan,
                    on_channel_changed=(self._manager.update_current_channel),
                    on_error=(self._on_background_error),
                )

        return LivePacketSource(
            self.config.interface_name,
            output_file=target.storage_path,
            pcap_reference=(target.pcap_reference),
            capture_session_id=(target.capture_session_id),
            display_filter=(self.config.display_filter),
            bpf_filter=(self.config.bpf_filter),
            capture_factory=(self._live_capture_factory),
        )

    def _finalize_evidence(self) -> None:
        target = self._evidence_target
        writer = self._evidence_writer

        if target is None or writer is None or not target.storage_path.exists():
            return

        try:
            self._last_evidence_metadata = writer.finalize(target)

        except Exception as error:
            logger.exception("Unable to finalize capture evidence")

            with self._lock:
                self._background_error = self._background_error or error

    def _on_processing_error(
        self,
        error: Exception,
        packet_number: int,
    ) -> None:
        logger.warning(
            "Skipping packet %d after processing error: %s",
            packet_number,
            type(error).__name__,
        )

    def _on_heartbeat_error(
        self,
        error: Exception,
    ) -> None:
        logger.warning(
            "Heartbeat publication failed: %s",
            type(error).__name__,
        )

    def _on_background_error(
        self,
        error: Exception,
    ) -> None:
        with self._lock:
            self._background_error = error

        self._manager.stop()


def _discard_heartbeat(
    record: object,
) -> None:
    del record


def _log_detection_event(
    event: DetectionEvent,
) -> None:
    """Log events when no backend event sink is injected."""

    logger.warning(
        "Detection event emitted: %s",
        json.dumps(
            event.to_dict(),
            sort_keys=True,
        ),
    )


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Run the WIDS capture and detection worker."),
    )

    source = parser.add_mutually_exclusive_group(required=True)

    source.add_argument(
        "--pcap",
        type=Path,
    )

    source.add_argument(
        "--interface",
    )

    parser.add_argument(
        "--window-seconds",
        type=float,
        action="append",
        required=True,
        help=("Feature window; repeat for multiple windows."),
    )

    parser.add_argument(
        "--runtime-pcap-directory",
        type=Path,
        default=Path("runtime/pcap"),
    )

    parser.add_argument(
        "--pcap-reference",
    )

    parser.add_argument(
        "--channel",
        type=int,
        action="append",
        default=[],
    )

    parser.add_argument(
        "--channel-dwell-seconds",
        type=float,
        default=1.0,
    )

    parser.add_argument(
        "--heartbeat-seconds",
        type=float,
        default=5.0,
    )

    parser.add_argument(
        "--worker-id",
        default="capture-worker",
    )

    parser.add_argument(
        "--detection-config",
        type=Path,
        help=("YAML configuration for the five detection rules."),
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
    )

    return parser


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """CLI entry point for replay and live capture."""

    args = _build_argument_parser().parse_args(argv)

    logging.basicConfig(
        level=getattr(
            logging,
            str(args.log_level).upper(),
            logging.INFO,
        ),
        format=("%(asctime)s %(levelname)s %(name)s %(message)s"),
    )

    source_mode = CaptureSource.PCAP if args.pcap is not None else CaptureSource.LIVE

    config = WorkerConfig(
        source_mode=source_mode,
        feature_window_seconds=tuple(args.window_seconds),
        runtime_pcap_directory=(args.runtime_pcap_directory),
        heartbeat_interval_seconds=(args.heartbeat_seconds),
        worker_id=args.worker_id,
        interface_name=args.interface,
        pcap_path=args.pcap,
        pcap_reference=args.pcap_reference,
        channels=tuple(args.channel),
        channel_dwell_seconds=(args.channel_dwell_seconds),
        detection_config_path=(args.detection_config),
    )

    worker = CaptureWorker(config)

    def request_stop(
        signum: int,
        frame: object,
    ) -> None:
        del signum, frame
        worker.stop()

    signal.signal(
        signal.SIGINT,
        request_stop,
    )

    signal.signal(
        signal.SIGTERM,
        request_stop,
    )

    try:
        status = worker.run()

    except Exception:
        logger.exception("Capture worker failed")

        return 1

    print(
        json.dumps(
            status.to_dict(),
            indent=2,
            sort_keys=True,
        )
    )

    return 0 if status.state.value == "stopped" else 1


if __name__ == "__main__":
    raise SystemExit(main())
