/*
 * USB Device Next stack init for the Auracast sniffer.
 *
 * On the nRF52840 dongle (no physical UART): two CDC-ACM class
 * instances land on the host, both descending from `zephyr_udc0` --
 * the board's default `board_cdc_acm_uart` (console + shell + logs)
 * and `cdc_acm_data` (binary pcap stream, added by the sample
 * overlay). USB Next auto-discovers and registers the CDC-ACM class
 * instances via `usbd_register_all_classes`.
 *
 * Adapted from `samples/subsys/usb/common/sample_usbd_init.c`.
 */

#include "usbd_setup.h"

#include <zephyr/device.h>
#include <zephyr/usb/usbd.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(sniffer_usbd, LOG_LEVEL_INF);

/* Zephyr project's assigned USB VID; safe for local/dev use. */
#define SNIFFER_USBD_VID     0x2fe3
#define SNIFFER_USBD_PID     0x520a
#define SNIFFER_USBD_MFR     "Zephyr Project"
#define SNIFFER_USBD_PRODUCT "Auracast BIS Sniffer"
#define SNIFFER_USBD_MAXPOW  250  /* x2mA = 500 mA */

USBD_DEVICE_DEFINE(sniffer_usbd,
		   DEVICE_DT_GET(DT_NODELABEL(zephyr_udc0)),
		   SNIFFER_USBD_VID, SNIFFER_USBD_PID);

USBD_DESC_LANG_DEFINE(sniffer_lang);
USBD_DESC_MANUFACTURER_DEFINE(sniffer_mfr, SNIFFER_USBD_MFR);
USBD_DESC_PRODUCT_DEFINE(sniffer_product, SNIFFER_USBD_PRODUCT);
IF_ENABLED(CONFIG_HWINFO, (USBD_DESC_SERIAL_NUMBER_DEFINE(sniffer_sn)));

USBD_DESC_CONFIG_DEFINE(sniffer_fs_cfg_desc, "FS Configuration");

USBD_CONFIGURATION_DEFINE(sniffer_fs_config,
			  USB_SCD_SELF_POWERED, SNIFFER_USBD_MAXPOW,
			  &sniffer_fs_cfg_desc);

int sniffer_usbd_enable(void)
{
	int err;

	err = usbd_add_descriptor(&sniffer_usbd, &sniffer_lang);
	if (err) {
		LOG_ERR("lang descriptor: %d", err);
		return err;
	}

	err = usbd_add_descriptor(&sniffer_usbd, &sniffer_mfr);
	if (err) {
		LOG_ERR("manufacturer descriptor: %d", err);
		return err;
	}

	err = usbd_add_descriptor(&sniffer_usbd, &sniffer_product);
	if (err) {
		LOG_ERR("product descriptor: %d", err);
		return err;
	}

	IF_ENABLED(CONFIG_HWINFO, (
		err = usbd_add_descriptor(&sniffer_usbd, &sniffer_sn);
		if (err) {
			LOG_ERR("SN descriptor: %d", err);
			return err;
		}
	));

	err = usbd_add_configuration(&sniffer_usbd, USBD_SPEED_FS,
				     &sniffer_fs_config);
	if (err) {
		LOG_ERR("add FS config: %d", err);
		return err;
	}

	err = usbd_register_all_classes(&sniffer_usbd, USBD_SPEED_FS, 1, NULL);
	if (err) {
		LOG_ERR("register classes: %d", err);
		return err;
	}

	/* Two CDC-ACM interfaces on the same configuration -> use the
	 * Interface Association Descriptor code triple. */
	usbd_device_set_code_triple(&sniffer_usbd, USBD_SPEED_FS,
				    USB_BCC_MISCELLANEOUS, 0x02, 0x01);

	usbd_self_powered(&sniffer_usbd, true);

	err = usbd_init(&sniffer_usbd);
	if (err) {
		LOG_ERR("usbd_init: %d", err);
		return err;
	}

	err = usbd_enable(&sniffer_usbd);
	if (err) {
		LOG_ERR("usbd_enable: %d", err);
		return err;
	}

	return 0;
}
