#!/usr/bin/env python3
"""Regressions for strict JSON decoding at conformance boundaries."""

from __future__ import annotations

import unittest

from strict_json import (
    DuplicateMemberError,
    InvalidJsonSyntaxError,
    InvalidUtf8Error,
    NonFiniteNumberError,
    decode_strict_json,
)


class StrictJsonTests(unittest.TestCase):
    def test_one_decoder_rejects_each_ambiguous_or_invalid_encoding(self) -> None:
        cases = (
            (b'{"member":1,"member":2}', DuplicateMemberError),
            (b'{"member":NaN}', NonFiniteNumberError),
            (b'{"member":"\xff"}', InvalidUtf8Error),
            (b'{"member":', InvalidJsonSyntaxError),
        )
        for serialized, expected_error in cases:
            with self.subTest(expected_error.__name__), self.assertRaises(
                expected_error
            ):
                decode_strict_json(serialized)

    def test_nested_values_and_legitimate_newlines_are_preserved(self) -> None:
        self.assertEqual(
            decode_strict_json(b'{"body":{"text":"line one\\nline two\\n"}}'),
            {"body": {"text": "line one\nline two\n"}},
        )


if __name__ == "__main__":
    unittest.main()
