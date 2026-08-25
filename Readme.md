# Auracast Hacker's Toolkit

This is a Zephyr-based security research toolkit for Bluetooth Auracast to do passive sniffing,
active BIS hijack (the [BISON attack](https://www.carloalbertoboano.com/documents/gasteiger23bison.pdf)),
encrypted-stream DoS ([BISQuit attack](TODO)), and broadcast cloning (WIP).
Built for the [nRF52840 USB Dongle](https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle).

This requires our [Zephyr Fork](https://github.com/auracast-research/zephyr)
due to patches in the Bluetooth Link Layer.

## Installation and Setup

If you want to build the Auracast Hacker's Toolkit yourself, you'll
need to set up a Zephyr development environment. Which is pretty
straight forward if you just follow the steps, but it does take some
time (and disk space). You'll also need Zephyr SDK 1.0 or newer, Python
3, `west`, `nrfutil`, Wireshark, and an nRF52840 USB Dongle.

Follow the steps in the [Zephyr Getting Started Guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html).
The manifest in this repository pulls the fork automatically, so you
can just run:

```
mkdir aht && cd aht # west needs a top-level dir, a .west will be in aht after west init
git clone https://github.com/auracast-research/auracast-hackers-toolkit.git
cd auracast-hackers-toolkit
west init -l .
west update
west zephyr-export
pip install -r zephyr/scripts/requirements.txt
```

If you have it all set up, you should be able to run `west build`
inside this repository's root directory. Make sure to have set the
correct virtualenv and your `ZEPHYR_BASE` environment variable:

```
west build -p always -b nrf52840dongle/nrf52840
```

Then flash the firmware over the dongle's built-in USB bootloader.
You'll need the legacy version of Nordic's
[nrfutil](https://github.com/NordicSemiconductor/pc-nrfutil) for this
to work:

```
nrfutil pkg generate --hw-version 52 --sd-req=0x00 \
        --application build/zephyr/zephyr.hex --application-version 1 \
        toolkit.zip
nrfutil dfu usb-serial -pkg toolkit.zip -p /dev/ttyACM<bootloader>
```

## Usage

Connect the dongle to your computer. You'll get two serial devices:
attach to the first one This is the CLI, the other carries the capture data.

```
picocom /dev/ttyACM0
```

**Scanning for Auracast Broadcasts**

1. Start scanning: `scan on`.
2. View the discovered broadcasts with `scan list` (`scan clear` to empty).
3. `scan biginfo` syncs to the advertiser's periodic advertisements
   and dumps the BIGInfo packet without establishing a BIG sync.
4. `scan bcode <target> <hex>` sets the Broadcast_Code for an encrypted BIG.

All the commands below take an optional `<target>` argument which
looks up a candidate from the scan list by index, address, or name
substring. Leave it out to use the first entry.

**Sniffing a Broadcast**

1. `sniff start` locks onto a broadcaster and establishes a BIG sync; `sniff stop` stops it.
2. The captured PDUs are streamed to the second serial device. Point
   Wireshark's extcap (`extcap/auracast_extcap.py`) on that device
   and pick the DLT matching your mode: `sniff mode m2` (the default)
   streams raw LL PDUs as `BLUETOOTH_LE_LL_WITH_PHDR`, `sniff mode
   m1` streams reassembled HCI ISO Data as `BLUETOOTH_HCI_H4`.
  
- `sniff raw` captures an encrypted BIG without a Broadcast_Code and forwards the ciphertext instead of the decrypted payload.
- `sniff greedy on` turns on greedy mode: sniffer tries to capture all subevents, including all pre- and retransmissions.
- `sniff payload_omit on` drops PDU payloads: can be helpful if payload is not important and a lot of packet loss is observed.

**BISQuit: DoS via MIC Failure**

BISQuit floods every data subevent of an encrypted BIS with random
ciphertext and a random MIC, so a receiver in range fails its MIC
check and drops its BIG sync.

1. `bisquit start` syncs to the target, and starts the flood.
2. `bisquit stop` stops the flood and tears everything down.

**BISON: BIS Hijack**

BISON injects forged BIS PDUs on top of a real broadcast, timed to
the real broadcaster's subevents. This is a partial reimplementation 
of the original [BISON PoC](https://github.com/TuGraz-ITI/zephyr) to 
also support moden Auracast configurations, such as interleaved packing
or multiple subevents.

- `bison sync` takes a passive snapshot of the target's BIG
   parameters - required before any injection.
- `bison tx <evt_offset> <bis> <intra_se> <llid> [hex_pdu]`
   schedules a single forged data PDU. `bison ctrl`, and `bison ctrl_loop` (with `bison ctrl_stop`) inject
   BIG Control PDUs instead.
- `bison early [<us>]` biases the injection earlier to win the
   capture effect (10-50us works well).
- `bison status` shows the snapshot and TX counters; `bison unsync`
   tears it down.

**Clone**

> This is currently WIP and does not properly work yet.

Clone reads the target's identity and BIGInfo and rebroadcasts it as
its own BIG with a fixed filler payload. Essentially a fake broadcast under the
same identity.

1. `clone start` start the clone (at 2x the target's PA rate).
2. `clone stop` tears it down, `clone status` shows its state.
