#!/usr/bin/env python3
"""Wireshark extcap for the Auracast BIS sniffer (nRF52840 dongle).

Reads framed records from a serial port (the sniffer's binary CDC-ACM
data endpoint) and writes a pcapng stream to the FIFO Wireshark supplies.

Supports two DLTs, matching the two modes:

  * M1: LINKTYPE_BLUETOOTH_HCI_H4 (187):
    Payload is a raw HCI H4 packet (type byte + HCI ISO Data body).

  * M2: LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256):
    Payload is a 10-byte BTLE pseudo-header + 4B AA + BIS PDU + 3B CRC
    placeholder, optionally followed by a controller-metadata trailer.
    Each EPB gets a pcapng opt_comment with the BIG-scoped state that
    wouldn't be on the air otherwise.

Pick the matching DLT in Wireshark's interface options before capture (firmware defaults to M2)

Format on the serial port. Each record starts with a magic identifying the record type:
    u16 LE  MAGIC     (0xB1E4U)
    u16 LE  LEN       (bytes to follow after LEN)
    u64 LE  DEV_TS_US (device uptime in microseconds)
    ...     PAYLOAD   (magic- and DLT-specific; see framing.h)

Install as a Wireshark extcap by symlinking or copying into one of:
    ~/.config/wireshark/extcap/
    ~/.local/lib/wireshark/extcap/
    /Applications/Wireshark.app/Contents/MacOS/extcap/ (On macOS sometimes only this one works?)

Depends on pyserial (`pip install pyserial`).
"""

from __future__ import annotations

import argparse
import struct
import sys
import time

try:
    import serial
except ImportError:
    serial = None  # only needed for --capture

# Record magics
WIRE_MAGIC_LL_PDU   = 0xB1E4
META_TRAILER_MAGIC  = 0xB1E7

# Any known top-level record magic. We resync the buffer to the nearest of
# these when we hit a length-check failure.
KNOWN_MAGICS = (WIRE_MAGIC_LL_PDU,)

DLT_HCI_H4          = 187
DLT_LE_LL_WITH_PHDR = 256

IFACE_NAME    = "auracast-nrf52840"
IFACE_DISPLAY = "Auracast Hackers Toolkit Sniffer (nRF52840 Dongle)"


# ---------------------------------------------------------------------------
# pcapng writer
# ---------------------------------------------------------------------------

# Block types (per pcapng spec).
BLK_SHB = 0x0A0D0D0A
BLK_IDB = 0x00000001
BLK_EPB = 0x00000006

SHB_BOM = 0x1A2B3C4D

# Standard option codes.
OPT_ENDOFOPT = 0
OPT_COMMENT  = 1
# SHB options.
SHB_OPT_HARDWARE = 2
SHB_OPT_OS       = 3
SHB_OPT_USERAPPL = 4
# IDB options.
IDB_OPT_NAME     = 2
IDB_OPT_TSRESOL  = 9


def _pad4(n: int) -> int:
    return (4 - (n % 4)) % 4


def _pack_option(code: int, payload: bytes) -> bytes:
    """One pcapng option: u16 code + u16 length + payload + padding to 4B."""
    length = len(payload)
    return struct.pack("<HH", code, length) + payload + (b"\x00" * _pad4(length))


def _finalize_block(body: bytes, block_type: int) -> bytes:
    """Wrap body with block_type + total_length header/trailer, padded."""
    # 12 bytes: type (4) + length (4) at head + length (4) at tail.
    # Body is expected to already be 4-byte aligned.
    total = 12 + len(body)
    return (
        struct.pack("<II", block_type, total)
        + body
        + struct.pack("<I", total)
    )


def emit_shb(out, appl_comment: str) -> None:
    body = struct.pack("<IHHq", SHB_BOM, 1, 0, -1)  # BOM, major, minor, section_len
    opts = b""
    opts += _pack_option(OPT_COMMENT, b"Auracast BIS sniffer capture")
    opts += _pack_option(SHB_OPT_HARDWARE, b"nRF52840 Dongle (PCA10059)")
    opts += _pack_option(SHB_OPT_USERAPPL, appl_comment.encode("utf-8"))
    opts += _pack_option(OPT_ENDOFOPT, b"")
    out.write(_finalize_block(body + opts, BLK_SHB))


def emit_idb(out, linktype: int, snaplen: int, iface_name: str) -> None:
    body = struct.pack("<HHI", linktype, 0, snaplen)  # linktype, reserved, snaplen
    opts = b""
    opts += _pack_option(IDB_OPT_NAME, iface_name.encode("utf-8"))
    opts += _pack_option(IDB_OPT_TSRESOL, bytes([6]))  # microsecond resolution
    opts += _pack_option(OPT_ENDOFOPT, b"")
    out.write(_finalize_block(body + opts, BLK_IDB))


def emit_epb(out, iface_id: int, ts_us: int, pkt: bytes, comment: str) -> None:
    ts_hi = (ts_us >> 32) & 0xFFFFFFFF
    ts_lo = ts_us & 0xFFFFFFFF
    caplen = len(pkt)
    origlen = caplen
    body = struct.pack("<IIIII", iface_id, ts_hi, ts_lo, caplen, origlen)
    body += pkt
    body += b"\x00" * _pad4(caplen)
    if comment:
        body += _pack_option(OPT_COMMENT, comment.encode("utf-8"))
    body += _pack_option(OPT_ENDOFOPT, b"")
    out.write(_finalize_block(body, BLK_EPB))


# ---------------------------------------------------------------------------
# Metadata decoding
# ---------------------------------------------------------------------------

# BIS PDU metadata trailer fields (16 bytes).
BIS_META_FMT = (
    "<"
    "H"     # event_counter
    "B"     # bis
    "B"     # chan
    "B"     # subevent
    "B"     # bn_curr
    "B"     # irc_curr
    "B"     # ptc_curr
    "B"     # cssn_curr
    "B"     # cssn_next
    "B"     # derived
    "B"     # seq (rolling per-record sequence, wraps mod 256)
    "I"     # payload_number (low 32 bits)
)
BIS_META_SIZE = struct.calcsize(BIS_META_FMT)

# SNIFFER_TAP_DFLAG_*.
DFLAG_RETRANSMISSION   = 1 << 0
DFLAG_PRETRANSMISSION  = 1 << 1
DFLAG_CONTROL          = 1 << 2
DFLAG_INTERLEAVED      = 1 << 3
DFLAG_FIRST_EVENT_RX   = 1 << 4
DFLAG_CIPHERTEXT       = 1 << 5

PHY_NAMES = {1: "1M", 2: "2M", 4: "coded"}


def decode_bis_meta(trailer: bytes) -> dict:
    if len(trailer) < BIS_META_SIZE:
        return {}
    (
        event_counter, bis, chan, subevent, bn_curr, irc_curr, ptc_curr,
        cssn_curr, cssn_next, derived, seq, payload_num,
    ) = struct.unpack_from(BIS_META_FMT, trailer, 0)
    return {
        "event_counter": event_counter,
        "bis":           bis,
        "chan":          chan,
        "subevent":      subevent,
        "bn_curr":       bn_curr,
        "irc_curr":      irc_curr,
        "ptc_curr":      ptc_curr,
        "cssn_curr":     cssn_curr,
        "cssn_next":     cssn_next,
        "derived":       derived,
        "seq":           seq,
        "payload_number": payload_num,
    }


def format_bis_meta_comment(bis_meta: dict) -> str:
    if not bis_meta:
        return ""
    d = bis_meta["derived"]
    parts = [
        f"event={bis_meta['event_counter']}",
        f"bis={bis_meta['bis']}",
        f"chan={bis_meta['chan']}",
        f"se={bis_meta['subevent']}",
        f"bn={bis_meta['bn_curr']}",
        f"irc={bis_meta['irc_curr']}",
        f"ptc={bis_meta['ptc_curr']}",
        f"cssn={bis_meta['cssn_curr']}/{bis_meta['cssn_next']}",
        f"payload_num={bis_meta['payload_number']}",
        f"seq={bis_meta['seq']}",
    ]
    if d & DFLAG_CONTROL:
        parts.append("kind=control")
    else:
        parts.append("kind=data")
    if d & DFLAG_RETRANSMISSION:
        parts.append("retransmission")
    if d & DFLAG_PRETRANSMISSION:
        parts.append("pretransmission")
    if d & DFLAG_INTERLEAVED:
        parts.append("packing=interleaved")
    if d & DFLAG_FIRST_EVENT_RX:
        parts.append("first_event_rx")
    if d & DFLAG_CIPHERTEXT:
        parts.append("payload=ciphertext")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Capture main loop
# ---------------------------------------------------------------------------

# Wire preamble is 12 bytes (magic + len + dev_ts).
PREAMBLE_LEN = 12

# For LL PDU records in M2 the fixed slice before the optional meta trailer:
#   phdr(10) + AA(4) + at least the 2 PDU header bytes + CRC(3) = 19
M2_MIN_PAYLOAD = 10 + 4 + 2 + 3


def _resync_to_magic(buf: bytearray) -> int:
    """Return index of the earliest known magic in buf, or -1."""
    best = -1
    for m in KNOWN_MAGICS:
        i = buf.find(struct.pack("<H", m))
        if i >= 0 and (best < 0 or i < best):
            best = i
    return best


def _extract_bis_meta_trailer(payload: bytes) -> tuple[bytes, dict]:
    """Split payload into (pcap_bytes, bis_meta_dict).

    payload layout (M2):  phdr(10) + AA(4) + PDU + CRC(3) [+ trailer]
    The trailer, if present, occupies the last (4 + BIS_META_SIZE) bytes
    and starts with u16 META_TRAILER_MAGIC. Locating from the tail
    avoids having to trust the PDU length byte, which is meaningless
    when the tap captured an empty record (radio failed, buffer starved).
    """
    if len(payload) < M2_MIN_PAYLOAD:
        return payload, {}

    trailer_hdr = 4  # META_MAGIC(2) + META_LEN(2)
    tail_len = trailer_hdr + BIS_META_SIZE
    if len(payload) < tail_len:
        return payload, {}

    trailer_start = len(payload) - tail_len
    magic, tlen = struct.unpack_from("<HH", payload, trailer_start)
    if magic != META_TRAILER_MAGIC or tlen != BIS_META_SIZE:
        return payload, {}

    trailer_body = payload[trailer_start + trailer_hdr :
                           trailer_start + trailer_hdr + tlen]
    return payload[:trailer_start], decode_bis_meta(trailer_body)


def do_capture(port: str, fifo_path: str, baud: int, linktype: int) -> None:
    if serial is None:
        print("pyserial not installed - `pip install pyserial`", file=sys.stderr)
        sys.exit(2)

    with open(fifo_path, "wb") as out:
        appl_comment = "auracast_extcap.py"
        emit_shb(out, appl_comment)
        emit_idb(out, linktype, 65535, IFACE_NAME)
        out.flush()

        try:
            with serial.Serial(port, baud, timeout=0.1) as ser:
                buf = bytearray()
                ts_offset_us: int | None = None
                while True:
                    chunk = ser.read(4096)
                    if not chunk:
                        continue
                    buf.extend(chunk)

                    while True:
                        # Find the earliest known magic in buf.
                        i = _resync_to_magic(buf)
                        if i < 0:
                            if len(buf) > 1:
                                del buf[:-1]
                            break
                        if i > 0:
                            del buf[:i]

                        if len(buf) < 4:
                            break
                        magic, plen = struct.unpack_from("<HH", buf, 0)
                        if len(buf) < 4 + plen:
                            break

                        rec = bytes(buf[4 : 4 + plen])
                        del buf[: 4 + plen]

                        if len(rec) < 8:
                            continue
                        dev_ts_us = struct.unpack_from("<Q", rec, 0)[0]
                        payload = rec[8:]

                        if ts_offset_us is None:
                            ts_offset_us = int(time.time() * 1_000_000) - dev_ts_us
                        ts_us = ts_offset_us + dev_ts_us

                        if magic == WIRE_MAGIC_LL_PDU:
                            if linktype == DLT_LE_LL_WITH_PHDR:
                                pkt, bis_meta = _extract_bis_meta_trailer(payload)
                                comment = format_bis_meta_comment(bis_meta)
                            else:
                                # M1 / HCI H4 - payload is the HCI packet
                                # unchanged, no controller-level trailer.
                                pkt = payload
                                comment = ""
                            emit_epb(out, 0, ts_us, pkt, comment)
                            out.flush()
        except (BrokenPipeError, KeyboardInterrupt):
            pass


def print_interfaces() -> None:
    print("extcap {version=0.3}{help=https://github.com/auracast-research/auracast-hackers-toolkit}")
    print(f"interface {{value={IFACE_NAME}}}{{display={IFACE_DISPLAY}}}")


def print_dlts() -> None:
    print(
        f"dlt {{number={DLT_HCI_H4}}}{{name=BLUETOOTH_HCI_H4}}"
        "{display=M1: HCI ISO SDUs}"
    )
    print(
        f"dlt {{number={DLT_LE_LL_WITH_PHDR}}}{{name=BLUETOOTH_LE_LL_WITH_PHDR}}"
        "{display=M2: Raw BIS PDUs}"
    )


def print_config() -> None:
    print(
        "arg {number=0}{call=--serial-port}{display=Serial port}"
        "{type=string}{default=/dev/ttyACM0}"
        "{tooltip=Path to the sniffer's data CDC-ACM (second /dev/ttyACM* on Linux, second COM* on Windows)}"
        "{required=true}"
    )
    print(
        "arg {number=1}{call=--baud}{display=Baud rate (ignored for CDC-ACM)}"
        "{type=integer}{default=1000000}"
        "{tooltip=CDC-ACM ignores baud rate; pyserial needs a value.}"
    )
    print(
        f"arg {{number=2}}{{call=--dlt-number}}{{display=DLT for pcap output}}"
        "{type=selector}"
        f"{{default={DLT_LE_LL_WITH_PHDR}}}"
        "{tooltip=Match sniffer mode in Auracast Hacker's Toolkit (Default: M2)}"
    )
    print(f"value {{arg=2}}{{value={DLT_LE_LL_WITH_PHDR}}}{{display=M2: Raw BIS PUDs}}")
    print(f"value {{arg=2}}{{value={DLT_HCI_H4}}}{{display=M1: HCI ISO SDUs}}")


def main() -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--extcap-version", nargs="?", default=None)
    ap.add_argument("--extcap-interfaces", action="store_true")
    ap.add_argument("--extcap-interface")
    ap.add_argument("--extcap-dlts", action="store_true")
    ap.add_argument("--extcap-config", action="store_true")
    ap.add_argument("--capture", action="store_true")
    ap.add_argument("--fifo")
    ap.add_argument("--serial-port", default="/dev/ttyACM0")
    ap.add_argument("--baud", type=int, default=1_000_000)
    ap.add_argument("--dlt-number", type=int, default=DLT_LE_LL_WITH_PHDR)
    args, _unknown = ap.parse_known_args()

    if args.extcap_interfaces:
        print_interfaces()
        return 0
    if args.extcap_dlts:
        print_dlts()
        return 0
    if args.extcap_config:
        print_config()
        return 0
    if args.capture:
        if not args.fifo:
            print("--capture requires --fifo", file=sys.stderr)
            return 2
        if args.dlt_number not in (DLT_HCI_H4, DLT_LE_LL_WITH_PHDR):
            print(f"unsupported --dlt-number {args.dlt_number}", file=sys.stderr)
            return 2
        do_capture(args.serial_port, args.fifo, args.baud, args.dlt_number)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
