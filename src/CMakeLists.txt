# SPDX-License-Identifier: Apache-2.0

target_sources(app PRIVATE
	main.c
)

target_sources(app PRIVATE
	scan.c
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

target_include_directories(app PRIVATE
	.
	sniff
)

target_include_directories(app PRIVATE
	${ZEPHYR_BASE}/subsys/bluetooth/controller/ll_sw/sniffer
)
