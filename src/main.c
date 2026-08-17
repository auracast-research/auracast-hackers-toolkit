#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/logging/log.h>

#include "sniff/usbd_setup.h"
#include "sniff/usb_out.h"
#include "sniff/framing.h"
#include "sniff/bis_sink.h"
#include "sniff/cli.h"
#include "sniff/ll_capture.h"

#include "scan.h"
#include "big_sync.h"

#include "clone.h"

LOG_MODULE_REGISTER(aht_main, LOG_LEVEL_INF);

#define LED0_NODE DT_ALIAS(led0)
#if DT_NODE_HAS_STATUS(LED0_NODE, okay)
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
#define HAS_LED 1
#endif

int main(void)
{
	int err;

#ifdef HAS_LED
	if (gpio_is_ready_dt(&led)) {
		gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	}
#endif

	err = sniffer_usbd_enable();
	if (err != 0 && err != -EALREADY) {
		LOG_ERR("usbd_enable: %d", err);
		return 0;
	}

	/* Give the host a moment to open both CDC-ACM ports (extcap +
	 * shell) so first log lines aren't lost. */
	k_sleep(K_MSEC(1500));

	LOG_INF("Auracast Hacker's Toolkit starting");

	err = sniffer_usb_out_init();
	if (err) {
		LOG_ERR("usb_out init: %d", err);
	}

	err = sniffer_framing_init();
	if (err) {
		LOG_ERR("framing init: %d", err);
	}

	err = bt_enable(NULL);
	if (err) {
		LOG_ERR("bt_enable: %d", err);
		return 0;
	}

	(void)sniffer_scan_init();
	(void)big_sync_init();

	(void)sniffer_bis_sink_init();
	(void)sniffer_cli_init();

	(void)sniffer_ll_capture_init();
	LOG_INF("sniff: LLL tap active - pcap DLT = LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256)");

	(void)clone_init();

	while (true) {
		bool active = false;

		active = active || sniffer_bis_sink_is_active();
		active = active || big_sync_is_active();
		active = active || clone_is_active();
#ifdef HAS_LED
		if (gpio_is_ready_dt(&led)) {
			gpio_pin_toggle_dt(&led);
		}
#endif
		k_sleep(K_MSEC(active ? 200 : 500));
	}
	return 0;
}
