from abc import ABC, abstractmethod
from uuid import UUID

from wids.detection.config import RuleConfig
from wids.detection.result import RuleEvaluationResult


class DetectionRule[FrameT](ABC):
    """Base interface implemented by every WIDS detection rule."""

    def __init__(
        self,
        config: RuleConfig,
    ) -> None:
        self._config = config

    @property
    def config(self) -> RuleConfig:
        return self._config

    @property
    def rule_code(self) -> str:
        return self._config.code

    @property
    def event_type(self) -> str:
        return self._config.event_type

    @abstractmethod
    def evaluate(
        self,
        frame: FrameT,
    ) -> RuleEvaluationResult:
        """Evaluate one normalized wireless frame."""

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        """Clear rule state associated with one capture session."""

        del capture_session_id
