#include "ll_capture.h"
#include "framing.h"
#include "cli.h"

#include <stdint.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/logging/log.h>

#include "sniffer_tap.h"

LOG_MODULE_REGISTER(sniffer_llcap, LOG_LEVEL_INF);

static atomic_t forwarded;
static atomic_t dropped;

static void on_tap_pdu(const struct sniffer_tap_pdu *rec)
{
	if (sniffer_cli_mode() != SNIFFER_MODE_M2) {
		return;
	}
	if (sniffer_framing_emit_ll_pdu(rec) == 0) {
		atomic_inc(&forwarded);
	} else {
		atomic_inc(&dropped);
	}
}

int sniffer_ll_capture_init(void)
{
	return sniffer_tap_register(on_tap_pdu);
}

uint32_t sniffer_ll_capture_forwarded(void)
{
	return (uint32_t)atomic_get(&forwarded);
}

uint32_t sniffer_ll_capture_dropped(void)
{
	return (uint32_t)atomic_get(&dropped);
}
