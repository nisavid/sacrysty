"""One strict JSON decoder for serialized conformance and adapter inputs."""

from __future__ import annotations

import json


class StrictJsonError(ValueError):
    """Serialized input is not one unambiguous JSON value."""


class DuplicateMemberError(StrictJsonError):
    """A JSON object repeats a member name."""

    def __init__(self, member: str) -> None:
        super().__init__(member)
        self.member = member


class NonFiniteNumberError(StrictJsonError):
    """A non-finite numeric constant is not valid JSON."""

    def __init__(self, value: str) -> None:
        super().__init__(value)
        self.value = value


class InvalidUtf8Error(StrictJsonError):
    """Serialized JSON is not UTF-8."""


class InvalidJsonSyntaxError(StrictJsonError):
    """Serialized input does not follow JSON syntax."""


def _object_without_duplicate_members(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise DuplicateMemberError(name)
        result[name] = value
    return result


def _reject_nonstandard_constant(value: str) -> object:
    raise NonFiniteNumberError(value)


def decode_strict_json(serialized: bytes) -> object:
    """Decode UTF-8 JSON without duplicates or non-finite constants."""

    try:
        text = serialized.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidUtf8Error from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_members,
            parse_constant=_reject_nonstandard_constant,
        )
    except json.JSONDecodeError as exc:
        raise InvalidJsonSyntaxError from exc
