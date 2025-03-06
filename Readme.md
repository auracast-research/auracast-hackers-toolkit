# Auracast Hacker's Toolkit

This requires our [Zephyr Fork](https://github.com/auracast-research/zephyr) due to patches in the Bluetooth Link Layer.

## Precompiled Builds

We provide builds for the [nRF5340 Audio Devkit](https://www.nordicsemi.com/Products/Development-hardware/nRF5340-Audio-DK) and the [nRF52480](https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle). Head over to the [Releases](https://github.com/auracast-research/auracast-hackers-toolkit/releases) page to download them.

**nRF52480 USB Dongle**

The dongle has a built-in USB bootloader, which makes it a bit annoying to flash the firmware. Follow the instructions over at the [Zephyr documentation](https://docs.zephyrproject.org/latest/boards/nordic/nrf52840dongle/doc/index.html#option-1-using-the-built-in-bootloader-only). You'll need the legacy version of Nordic's [nrfutil](https://github.com/NordicSemiconductor/pc-nrfutil) for this to work.

**nRF5340 Audio DK**

The nRF5340 devkit requires two firmware files to be flashed. You'll also need the [nRF Command Line Tools](https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools) to flash the firmware files. You can then flash the FW as follows:

```
# erase current FW
nrfjprog --eraseall
# flash host FW
nrfjprog --program host.hex --verify
# flash controller FW to network coprocessor
nrfjprog --program controller.hex --coprocessor CP_NETWORK --verify
```

## Installation and Setup

If you want to build the Auracast Hacker's Toolkit yourself, you'll need to set up a Zephyr development environment. Which is pretty straight forward if you just follow the steps, but it does take some time and disk space.

Follow the steps in the [Zephyr Getting Started Guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html), but when running `west init`, you'll need to specify our Zephyr fork with the link layer patches. So instead, you should run:

```
west init ~/zephyrproject -m git@github.com:auracast-research/zephyr.git
```

If you have it all set up, you should be able to run `west build` inside this repository's root directory. Make sure to have set the correct virtualenv and your `ZEPHYR_BASE` environment variable is set to the Zephyr directory you just created.

Depending on the devkit you can now build the firmware.

**nRF52480 USB Dongle**

```
west build -b nrf52840dongle/nrf52840
```

Then flash as described above.

**nRF5340 Audio DK**

```
west build -b nrf5340_audio_dk/nrf5340/cpuapp --sysbuild -- -DOVERLAY_CONFIG=overlay-bt_ll_sw_split.conf
```

Flashing is easy, just run:

```
west flash
```

This will flash both the application and the network core.


## Usage

Connect the board to your computer and attach to the board's serial interface. If you're using the nRF5340 devkit, two TTYs will appear. Use the first one.

You can use picocom (or whatever tool you prefer) to connect to the interface with `115200` baud.
```
picocom /dev/ttyUSB0 -b 115200
```

Whenever you insert or reboot the board, you'll have to initialize the Bluetooth stack by running `init`!

**Scanning for Auracast Broadcasts**

1. Start scanning: `scan on`.
1. Once broadcasts are discovered, you can gather more information about them by running `scan biginfo`. This command will sync to the advertiser's periodic advertisements and gather the BIGInfo packet.
1. You can view the gathered information by running `broadcast list`.

**Dumping Raw BIS PDUs**

1. Run `broadcast list` and choose your target stream.
2. Run `broadcast dump $INDEX` and reference the targeted broadcast by its index.

It will now dump raw BIS PDUs[ˆ1] and raw BIGInfo payloads. If you want to use these packets (e.g. with [BISCracker](https://github.com/auracast-research/biscrack)), you can start picocom so that it dumps all output to a file:

```
picocom /dev/ttyUSB0 -b 115200 -g pdu_log.txt
```

[ˆ1]: Not entirely raw, the PDUs will already be ordered and not contain retransmissions or pretransmissions.

