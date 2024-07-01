"""
Generate time-sortable UUIDs (version 7) (RFC 9562)

Provides a `uuid7` function that's either directly imported from Python's `uuid` module
(if it's available) or an implementation based on a pull request to add it to CPython.
"""

import os
import uuid

if hasattr(uuid, "uuid7"):
    # Future Python versions will (hopefully) have this function built-in
    # Issue: https://github.com/python/cpython/issues/89083
    uuid7 = uuid.uuid7
else:
    # Taken from the CPython pull request:
    # * https://github.com/python/cpython/pull/121119
    # * Commit (2024-06-28T09:40:44Z)
    # * https://github.com/python/cpython/blob/bcd1417e8c8a1d23091930d6e5ca3190873d7191/Lib/uuid.py#L723-L779
    # Modifications:
    # * Added noqa comments to supress ruff warnings
    # * Manually set the variant and version bits.

    _last_timestamp_v7 = None
    _last_counter_v7 = 0  # 42-bit counter

    def uuid7():
        """Generate a UUID from a Unix timestamp in milliseconds and random bits.

        UUIDv7 objects feature monotonicity within a millisecond.
        """
        # --- 48 ---   -- 4 --   --- 12 ---   -- 2 --   --- 30 ---   - 32 -
        # unix_ts_ms | version | counter_hi | variant | counter_lo | random
        #
        # 'counter = counter_hi | counter_lo' is a 42-bit counter constructed
        # with Method 1 of RFC 9562, §6.2, and its MSB is set to 0.
        #
        # 'random' is a 32-bit random value regenerated for every new UUID.
        #
        # If multiple UUIDs are generated within the same millisecond, the LSB
        # of 'counter' is incremented by 1. When overflowing, the timestamp is
        # advanced and the counter is reset to a random 42-bit integer with MSB
        # set to 0.

        def get_counter_and_tail():
            rand = int.from_bytes(os.urandom(10))
            # 42-bit counter with MSB set to 0
            counter = (rand >> 32) & 0x1ffffffffff
            # 32-bit random data
            tail = rand & 0xffffffff
            return counter, tail

        global _last_timestamp_v7
        global _last_counter_v7

        import time
        nanoseconds = time.time_ns()
        timestamp_ms, _ = divmod(nanoseconds, 1_000_000)

        if _last_timestamp_v7 is None or timestamp_ms > _last_timestamp_v7:
            counter, tail = get_counter_and_tail()
        else:
            if timestamp_ms < _last_timestamp_v7:
                timestamp_ms = _last_timestamp_v7 + 1
            # advance the counter
            counter = _last_counter_v7 + 1
            if counter > 0x3ffffffffff:
                timestamp_ms += 1  # advance the timestamp
                counter, tail = get_counter_and_tail()
            else:
                tail = int.from_bytes(os.urandom(4))

        _last_timestamp_v7 = timestamp_ms
        _last_counter_v7 = counter

        int_uuid_7 = (timestamp_ms & 0xffffffffffff) << 80
        int_uuid_7 |= ((counter >> 30) & 0xfff) << 64
        int_uuid_7 |= (counter & 0x3fffffff) << 32
        int_uuid_7 |= tail & 0xffffffff

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
