"""
Generate time-sortable UUIDs (version 7)

Provides a `uuid7` function that's either directly imported from Python's `uuid` module
(if it's available) or an implementation based on a pull request to add it to CPython.
"""

import uuid

if hasattr(uuid, "uuid7"):
    # Future Python versions will (hopefully) have this function built-in
    # Issue: https://github.com/python/cpython/issues/89083
    uuid7 = uuid.uuid7
else:
    # Taken from the CPython pull request:
    # * https://github.com/python/cpython/pull/120650
    # * Commit (2024-06-21T21:40:33Z)
    # * https://github.com/python/cpython/blob/55edd0c04d6578c0b1da280ba981db4f41f46b94/Lib/uuid.py#L768-L786
    # Modifications:
    # * Added noqa comments to supress ruff warnings
    # * Manually set the variant and version bits.

    _last_timestamp_v7 = None

    def uuid7():
        """Generate a UUID from a Unix timestamp in milliseconds and random bits."""
        global _last_timestamp_v7  # noqa: PLW0603 (global-statement)
        import os  # noqa: PLC0415 (import-outside-toplevel)
        import time  # noqa: PLC0415 (import-outside-toplevel)

        nanoseconds = time.time_ns()
        timestamp_ms = nanoseconds // 1_000_000
        if _last_timestamp_v7 is not None and timestamp_ms <= _last_timestamp_v7:
            timestamp_ms = _last_timestamp_v7 + 1
        _last_timestamp_v7 = timestamp_ms
        int_uuid_7 = (timestamp_ms & 0xFFFFFFFFFFFF) << 80
        # Ideally, we would have 'rand_a' = first 12 bits of 'rand'
        # and 'rand_b' = lowest 62 bits, but it is easier to test
        # when we pick 'rand_a' from the lowest bits of 'rand' and
        # 'rand_b' from the next 62 bits, ignoring the 6 first bits
        # of 'rand'.
        rand = int.from_bytes(os.urandom(10))  # 80 random bits (ignore 6 first)
        int_uuid_7 |= (rand & 0x0FFF) << 64  # rand_a
        int_uuid_7 |= (rand >> 12) & 0x3FFFFFFFFFFFFFFF  # rand_b

        # Manually set the variant and version bits, to avoid a
        # `ValueError('illegal version number')` when calling the UUID constructor
        # with `version` set to 7.
        # Copied from UUID.__init__, hardcoded version:
        # https://github.com/python/cpython/blob/a86e6255c371e14cab8680dee979a7393b339ce5/Lib/uuid.py#L219-L224

        # Set the variant to RFC 4122.
        int_uuid_7 &= ~(0xC000 << 48)
        int_uuid_7 |= 0x8000 << 48
        # Set the version number to 7.
        int_uuid_7 &= ~(0xF000 << 64)
        int_uuid_7 |= 7 << 76

        return uuid.UUID(int=int_uuid_7)
