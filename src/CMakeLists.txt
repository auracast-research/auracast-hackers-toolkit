# SPDX-License-Identifier: Apache-2.0

target_sources(app PRIVATE
	main.c
)

# `scan` is the shared device-discovery + config front-end.
# big_sync.c is the PA + BIG sync helper used by `bison sync` and
# `bisquit start` 
target_sources(app PRIVATE
	scan.c
	big_sync.c
)

# --- sniff subsystem ---------------------------------------------------
target_sources(app PRIVATE
	sniff/bis_sink.c
	sniff/cli.c
	sniff/framing.c
	sniff/ll_capture.c
	sniff/usbd_setup.c
	sniff/usb_out.c
)

# --- bison subsystem ---------------------------------------------------
# The BISON LL machinery (bison_lll_hijack, bison_tx, bison_sniff, ...)
# lives in the Zephyr fork at subsys/bluetooth/controller/ll_sw/bison/.
# Only the shell front-end lives here.
target_sources(app PRIVATE
	bison/cli.c
)

target_include_directories(app PRIVATE
	.
	sniff
	bison
)

target_include_directories(app PRIVATE
	${ZEPHYR_BASE}/subsys/bluetooth/controller/ll_sw/sniffer
)

# The BISON + bisquit CLI sources include internal Zephyr controller
# headers (hal/ticker.h, pdu.h, lll/pdu_vendor.h, ...). 
target_include_directories(app PRIVATE
	${ZEPHYR_BASE}/subsys/bluetooth/controller
	${ZEPHYR_BASE}/subsys/bluetooth/controller/ll_sw
	${ZEPHYR_BASE}/subsys/bluetooth/controller/ll_sw/nordic
	${ZEPHYR_BASE}/subsys/bluetooth/controller/ll_sw/nordic/lll
	${ZEPHYR_BASE}/subsys/bluetooth/controller/ll_sw/bison
)
