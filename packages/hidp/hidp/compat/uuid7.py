"""
Generate time-sortable UUIDs (version 7) (RFC 9562).

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
    # * https://github.com/python/cpython/blob/ef85b200602ab00c23ef158813fa57076f561cfd/Lib/uuid.py#L752-L815
    # Modifications:
    # * Added noqa comments to supress ruff warnings
    # * Minor formatting changes
    # * Use int constructor argument instead of private _from_int method,
    #   the latter does not (yet) exist

    _RFC_4122_VERSION_7_FLAGS = (7 << 76) | (0x8000 << 48)
    _last_timestamp_v7 = None
    _last_counter_v7 = 0  # 42-bit counter

    def uuid7():
        """
        Generate a UUID from a Unix timestamp in milliseconds and random bits.

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
            counter = (rand >> 32) & 0x1FF_FFFF_FFFF
            # 32-bit random data
            tail = rand & 0xFFFF_FFFF
            return counter, tail

        global _last_timestamp_v7, _last_counter_v7  # noqa: PLW0603

        import time  # noqa: PLC0415

        nanoseconds = time.time_ns()
        timestamp_ms = nanoseconds // 1_000_000

        if _last_timestamp_v7 is None or timestamp_ms > _last_timestamp_v7:
            counter, tail = get_counter_and_tail()
        else:
            if timestamp_ms < _last_timestamp_v7:
                timestamp_ms = _last_timestamp_v7 + 1
            # advance the 42-bit counter
            counter = _last_counter_v7 + 1
            if counter > 0x3FF_FFFF_FFFF:  # noqa: PLR2004
                timestamp_ms += 1  # advance the 48-bit timestamp
                counter, tail = get_counter_and_tail()
            else:
                tail = int.from_bytes(os.urandom(4))

        _last_timestamp_v7 = timestamp_ms
        _last_counter_v7 = counter

        unix_ts_ms = timestamp_ms & 0xFFFF_FFFF_FFFF
        counter_msbs = counter >> 30
        counter_hi = counter_msbs & 0x0FFF  # keep 12 bits and clear variant bits
        counter_lo = counter & 0x3FFF_FFFF  # keep 30 bits and clear version bits

        int_uuid_7 = unix_ts_ms << 80
        int_uuid_7 |= counter_hi << 64
        int_uuid_7 |= counter_lo << 32
        int_uuid_7 |= tail & 0xFFFF_FFFF
        # by construction, the variant and version bits are already cleared
        int_uuid_7 |= _RFC_4122_VERSION_7_FLAGS

        return uuid.UUID(int=int_uuid_7)
