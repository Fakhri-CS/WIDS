from collections.abc import Iterable, Mapping
from typing import Final, cast

_MISSING: Final = object()


def _resolve_field_path(
    source: object,
    field_path: str,
) -> object:
    """Resolve a dotted field path from an object or mapping."""

    segments = field_path.split(".")

    if not field_path or any(not segment for segment in segments):
        raise ValueError("Required field paths must use non-empty dotted segments")

    current: object = source

    for segment in segments:
        if current is None:
            return _MISSING

        if isinstance(current, Mapping):
            mapping = cast(Mapping[object, object], current)
            current = mapping.get(segment, _MISSING)
        else:
            current = getattr(current, segment, _MISSING)

        if current is _MISSING:
            return _MISSING

    return current


def find_missing_fields(
    source: object,
    required_fields: Iterable[str],
) -> tuple[str, ...]:
    """Return required fields that are absent or contain None."""

    missing_fields: list[str] = []
    processed_fields: set[str] = set()

    for field_path in required_fields:
        if field_path in processed_fields:
            continue

        processed_fields.add(field_path)
        value = _resolve_field_path(source, field_path)

        if value is _MISSING or value is None:
            missing_fields.append(field_path)

    return tuple(missing_fields)


def has_required_fields(
    source: object,
    required_fields: Iterable[str],
) -> bool:
    """Return whether all required fields are available."""

    return not find_missing_fields(
        source,
        required_fields,
    )
