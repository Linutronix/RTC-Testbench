#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright(C) 2026 Intel Corporation
# Authors:
#   Hector Blanco Alcaine


"""
UDP JSON Stats Translator
=========================

This script transforms the statistics payload from JSON to fixed-length keys
and values. This allows receivers with limited parsing capabilities to extract
and display the stats.

In a little bit more detail, it:

1. Receives UDP packets with RTC TB stats on localhost:<port>
2. Parses the RTC Testbench JSON payload
3. Transforms it into a sequence of fixed-length key string plus uint64 value
4. Forwards the result as the payload of a UDP packet to <dest_ip>:<port>

The parameter "measurement" can be used to select the measurements to be
forwarded. E.g. "soc" will add the internal latency metrics.

Usage:
    python3 udp_json_to_fixed.py <dest_ip> <port> <measurement>

Examples:
    python3 udp_json_to_fixed.py 192.168.1.100 5005 default
    python3 udp_json_to_fixed.py 192.168.1.100 5005 soc

Fixed-length format:
    - Key   : 28 ASCII characters, left-padded with spaces
    - Value : a 64 bit unsigned integer
"""

import logging
import json
import socket
import struct
import sys



KEY_LEN        = 28                   # Fixed key field width (chars)
VALUE_LEN      = 8                    # Unsigned ints 64b
ENTRY_LEN      = KEY_LEN + VALUE_LEN

# The maximum value of a 64-bit unsigned integer is 2^64 - 1 = 18446744073709551615
# That is 20 decimal digits → used to pad the printed value field
_UINT64_MAX_STR_LEN = len(str(0xFFFF_FFFF_FFFF_FFFF))

RECV_BUF_SIZE  = 65535                # Maximum UDP payload size
LOCALHOST      = "127.0.0.1"

# SoC metrics
SOC_METRICS = ['RxMin', 'RxMax',
               'TxMin', 'TxMax',

               'RxHw2XdpMin', 'RxHw2XdpMax',
               'RxXdp2AppMin', 'RxXdp2AppMax',

               'TxHwTimestampingMissing'
              ]

# We only forward the messages below
WHITELIST_MIRROR    = ['FramesSent', 'FramesReceived',
                       'OnewayMin', 'OnewayMax', 'OnewayAv',
                       'OutofOrderErrors', 'FrameIdErrors', 'PayloadErrors',
                       'OnewayOutliers',
                       ]

WHITELIST_REFERENCE = ['FramesSent', 'FramesReceived',
                       'OnewayMin', 'OnewayMax', 'OnewayAv',
                       'OutofOrderErrors', 'FrameIdErrors', 'PayloadErrors',
                       'OnewayOutliers',

                       'RoundTripTimeMin', 'RoundTripMax', 'RoundTripAv',
                       'RoundTripOutliers']

# Use these constants to enable and disable printing the messages
# TODO: provide command line options to set them
TRACE_INPUT = False
TRACE_OUTPUT = True


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)




def encode_entry(key: str, value: str) -> bytes:
    """
    Encode a key/value string pair into a fixed-size binary record.

    Layout (ENTRY_LEN = KEY_LEN + VALUE_LEN bytes total):
    ┌──────────────────────────────┬──────────────────────┐
    │  key  (KEY_LEN bytes ASCII)  │  value  (8 bytes)    │
    │  left-padded with spaces     │  uint64, big-endian  │
    └──────────────────────────────┴──────────────────────┘

    Parameters
    ----------
    key   : str  – Arbitrary string key.
                   Only the first KEY_LEN characters are used.
                   The result is left-padded with ASCII spaces so that
                   the field is always exactly KEY_LEN bytes wide.
    value : str  – String representation of a non-negative integer.
                   Converted to a 64-bit unsigned integer and packed
                   in network (big-endian) byte order.

    Returns
    -------
    bytes – ENTRY_LEN bytes ready for binary transmission.

    Raises
    ------
    ValueError  – If value cannot be parsed as a non-negative integer,
                  or if it exceeds the range of a uint64
                  (0 … 2**64 − 1).
    UnicodeEncodeError – If key contains non-ASCII characters.
    """

    # Truncate to at most KEY_LEN characters, then encode as ASCII.
    key_truncated: str   = key[:KEY_LEN]
    key_bytes:     bytes = key_truncated.encode("ascii")

    # Left-pad with ASCII spaces so the field is exactly KEY_LEN bytes.
    key_field: bytes = key_bytes.rjust(KEY_LEN, b" ")   # b" " == 0x20

    int_value: int = int(value)          # raises ValueError on bad input
    if not (0 <= int_value <= 0xFFFF_FFFF_FFFF_FFFF):
        raise ValueError(
            f"value {int_value} is out of range for a 64-bit unsigned integer "
            f"(0 … {0xFFFF_FFFF_FFFF_FFFF})."
        )

    # ">Q" → big-endian (network order), unsigned 64-bit integer
    value_field: bytes = struct.pack(">Q", int_value)

    # Assemble & sanity-check
    entry: bytes = key_field + value_field
    assert len(entry) == ENTRY_LEN, (          # should never fire
        f"BUG: entry length {len(entry)} != ENTRY_LEN {ENTRY_LEN}"
    )

    return entry


def transform_payload(raw_json: bytes, metrics) -> bytes:
    """
    Parse the incoming JSON payload and produce the output binary payload.

    Input JSON structure
    --------------------
    {
        "testbench": {
            "Timestamp": <value>,
            "MeasurementName": "<string>",
            "stats": {
                "TCName": "<TshHigh|TsnLow>",
                "StatName0": <value>,
                ...
                "StatNameN": <value>,
                // possibly another TCName block follows
            }
        }
    }

    Output binary structure
    -----------------------
    [MeasurementName entry]
    [<TCName><StatName0> entry]
    [<TCName><StatName1> entry]
    ...  (repeated for every TCName block)

    For example, the output once decoded would look like:
               crypto-mirror                    0
           TsnHighFramesSent             91187776
       TsnHighFramesReceived             91187776
            TsnHighOnewayMin                  396
            TsnHighOnewayMax                  830
             TsnHighOnewayAv                  425
     TsnHighOutofOrderErrors                    0
        TsnHighFrameIdErrors                    0
        TsnHighPayloadErrors                    0
       TsnHighOnewayOutliers                    0

    Returns
    -------
    bytes – concatenated fixed-length entries
    """
    data = json.loads(raw_json.decode("utf-8"))

    if TRACE_INPUT:
        print(json.dumps(data, indent=4))

    tb = data["testbench"]
    measurement_name = tb["MeasurementName"]
    stats            = tb["stats"]

    output_entries: list[bytes] = []

    output_entries.append(encode_entry(measurement_name, 0))

    # Select whitelist based on the measurement name
    if "reference" in measurement_name:
        whitelist = WHITELIST_REFERENCE
    elif "mirror" in measurement_name:
        whitelist = WHITELIST_MIRROR
    else:
        raise ValueError(
            f"Cannot match measurement '{measurement_name}' to mirror or reference."
        )

    if metrics == "soc":
        whitelist += SOC_METRICS


    # Walk the stats dict in insertion order.
    # Each time we encounter a "TCName" key we start a new block;
    # all subsequent keys (until the next "TCName") belong to that block.
    current_tc: str | None = None

    for stat_key, stat_value in stats.items():
        if stat_key == "TCName":
            current_tc = stat_value   # e.g. "TshHigh" or "TsnLow"
        elif stat_key in whitelist:
            if current_tc is None:
                raise ValueError(
                    f"Encountered stat '{stat_key}' before any TCName entry."
                )
            # Prepend TCName to the stat name to form the output key
            composite_key = f"{current_tc}{stat_key}"
            output_entries.append(encode_entry(composite_key, stat_value))
        else:
            # We do not forward the stat 'stat_key'
            continue

    return b"".join(output_entries)


def print_entry(entry: bytes) -> None:
    """
    Decode and print a binary record produced by encode_entry().

    Binary layout expected (ENTRY_LEN bytes total):
    ┌──────────────────────────────┬──────────────────────┐
    │  key  (KEY_LEN bytes ASCII)  │  value  (8 bytes)    │
    │  right-padded with NUL bytes │  uint64, big-endian  │
    └──────────────────────────────┴──────────────────────┘

    Output format:
        "<key> <value>"
    where:
      • <key>   is the ASCII string with trailing NUL / zero bytes stripped,
                printed exactly as stored (no extra padding).
      • <value> is the decimal representation of the uint64, left-padded
                with spaces to _UINT64_MAX_STR_LEN (20) characters, i.e.
                wide enough to always fit the largest possible uint64.

    Parameters
    ----------
    entry : bytes
        Exactly ENTRY_LEN bytes, as returned by encode_entry().

    Raises
    ------
    ValueError
        If len(entry) != ENTRY_LEN.
    """

    if len(entry) != ENTRY_LEN:
        raise ValueError(
            f"entry must be exactly {ENTRY_LEN} bytes, got {len(entry)}."
        )

    # First KEY_LEN bytes
    key_field: bytes = entry[:KEY_LEN]

    # Strip trailing NUL (zero) bytes, then decode as ASCII.
    # rstrip(b"\x00") removes only right-side zero bytes, preserving
    # any intentional spaces that are part of the actual key text.
    key_str: str = key_field.rstrip(b"\x00").decode("ascii")

    # Last VALUE_LEN bytes
    value_field: bytes = entry[KEY_LEN:]

    # ">Q" → big-endian (network order), unsigned 64-bit integer
    (int_value,) = struct.unpack(">Q", value_field)

    # Left-pad the decimal representation with spaces to the width of
    # the largest uint64 (20 digits).
    value_str: str = str(int_value).rjust(_UINT64_MAX_STR_LEN)

    print(f"{key_str} {value_str}")


def run(dest_ip: str, port: int, metrics) -> None:
    """
    Open a UDP socket bound to localhost:<port>, receive packets in a loop,
    transform each payload, and forward the result to dest_ip:<port>.
    """
    # Receiving socket – bound to localhost on the given port
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind((LOCALHOST, port))
    log.info("Listening for UDP packets on %s:%d", LOCALHOST, port)

    # Sending socket – unbound, used only for sending
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log.info("Will forward transformed packets to %s:%d", dest_ip, port)

    try:
        while True:
            raw_data, sender_addr = recv_sock.recvfrom(RECV_BUF_SIZE)
            log.info(
                "Received %d bytes from %s:%d",
                len(raw_data), sender_addr[0], sender_addr[1]
            )

            try:
                output_payload = transform_payload(raw_data, metrics)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                log.error("Failed to transform payload: %s", exc)
                continue   # Drop malformed packet; keep running

            send_sock.sendto(output_payload, (dest_ip, port))
            log.info(
                "Sent %d bytes (%d entries) to %s:%d",
                len(output_payload),
                len(output_payload) // ENTRY_LEN,
                dest_ip,
                port,
            )

            if TRACE_OUTPUT:
                # Slice in ENTRY_LEN size chunks
                metrics = [output_payload[i : i + ENTRY_LEN] for i in range(0, len(output_payload), ENTRY_LEN)]
                for metric in metrics:
                    print_entry(metric)


    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        recv_sock.close()
        send_sock.close()


def parse_args():

    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <dest_ip> <port> [default|soc]")
        print(f"Example: {sys.argv[0]} 192.168.1.100 5005 default")
        sys.exit(1)

    dest_ip = sys.argv[1]
    try:
        port = int(sys.argv[2])
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        print("Error: <port> must be an integer between 1 and 65535.")
        sys.exit(1)

    try:
        metrics = sys.argv[3]
        if metrics not in ['default', 'soc']:
            raise ValueError
    except ValueError:
        print("Error: <metrics> must be either 'default' or 'soc'")
        sys.exit(1)

    return dest_ip, port, metrics


def main() -> None:

    dest_ip, port, metrics = parse_args()

    run(dest_ip, port, metrics)




if __name__ == "__main__":
    main()
