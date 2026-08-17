#include "bis_sink.h"
#include "framing.h"
#include "cli.h"
#include "big_sync.h"

#include "clone.h"

#include "sniffer_tap.h"

#include <zephyr/sys/atomic.h>

static atomic_t single_bis_mode;

void sniffer_bis_sink_set_single_bis(bool on)
{
	atomic_set(&single_bis_mode, on ? 1 : 0);
}

bool sniffer_bis_sink_get_single_bis(void)
{
	return atomic_get(&single_bis_mode) != 0;
}

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net_buf.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci_types.h>
#include <zephyr/bluetooth/iso.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(sniffer_bis, LOG_LEVEL_INF);

#define PA_SYNCED_TIMEOUT_MS   2000
#define BIGINFO_TIMEOUT_MS     3000
#define BIS_UP_TIMEOUT_MS     10000
#define PA_RETRY_COUNT            6

#define SNIFFER_BIS_HANDLE_BASE 0x100

static struct bt_iso_chan_io_qos bis_rx_qos[CONFIG_BT_ISO_MAX_CHAN];
static struct bt_iso_chan_qos    bis_qos[CONFIG_BT_ISO_MAX_CHAN];
static struct bt_iso_chan        bis_iso_chan[CONFIG_BT_ISO_MAX_CHAN];
static struct bt_iso_chan       *bis_ptrs[CONFIG_BT_ISO_MAX_CHAN];
static uint16_t                  handles_for_bis[CONFIG_BT_ISO_MAX_CHAN];

static struct bt_le_per_adv_sync *pa;
static struct bt_iso_big         *big;

static struct bt_iso_biginfo cached_biginfo;
static bt_addr_le_t          cached_biginfo_addr;
static uint8_t               connected_count;

static K_SEM_DEFINE(sem_pa_synced, 0, 1);
static K_SEM_DEFINE(sem_biginfo,   0, 1);
static K_SEM_DEFINE(sem_bis_up,    0, CONFIG_BT_ISO_MAX_CHAN);
static K_SEM_DEFINE(sem_bis_lost,  0, CONFIG_BT_ISO_MAX_CHAN);

/* ----- ISO channel callbacks ----- */

static void iso_recv(struct bt_iso_chan *chan,
		     const struct bt_iso_recv_info *info,
		     struct net_buf *buf)
{
	/*
	 * We only emit into the pcap stream when runtime mode is M1
	 * (HCI ISO Data). Mixing M1 and M2 records would corrupt the
	 * pcap stream, which uses a single DLT.
	 */
	if (sniffer_cli_mode() != SNIFFER_MODE_M1) {
		return;
	}

	ptrdiff_t idx = chan - &bis_iso_chan[0];
	if (idx < 0 || idx >= CONFIG_BT_ISO_MAX_CHAN) {
		return;
	}
	(void)sniffer_framing_emit_iso_sdu(handles_for_bis[idx], info,
					   buf->data, buf->len);
}

static void iso_connected(struct bt_iso_chan *chan)
{
	if (sniffer_cli_mode() == SNIFFER_MODE_M1) {
		const struct bt_iso_chan_path hci_path = {
			.pid    = BT_ISO_DATA_PATH_HCI,
			.format = BT_HCI_CODING_FORMAT_TRANSPARENT,
		};
		int err;

		err = bt_iso_setup_data_path(chan, BT_HCI_DATAPATH_DIR_CTLR_TO_HOST,
					     &hci_path);
		if (err) {
			LOG_ERR("BIS data-path setup failed: %d", err);
		}
	}

	ptrdiff_t idx = chan - &bis_iso_chan[0];
	LOG_INF("BIS %ld connected (handle 0x%03x)", (long)idx,
		handles_for_bis[idx]);
	connected_count++;
	k_sem_give(&sem_bis_up);
}

static void iso_disconnected(struct bt_iso_chan *chan, uint8_t reason)
{
	ptrdiff_t idx = chan - &bis_iso_chan[0];
	LOG_INF("BIS %ld disconnected (reason 0x%02x)", (long)idx, reason);
	if (connected_count > 0U) {
		connected_count--;
	}
	if (reason != BT_HCI_ERR_OP_CANCELLED_BY_HOST) {
		k_sem_give(&sem_bis_lost);
	}
}

static struct bt_iso_chan_ops iso_ops = {
	.recv         = iso_recv,
	.connected    = iso_connected,
	.disconnected = iso_disconnected,
};

/* ----- PA sync callbacks ----- */

static void pa_synced_cb(struct bt_le_per_adv_sync *sync,
			 struct bt_le_per_adv_sync_synced_info *info)
{
	ARG_UNUSED(sync);
	ARG_UNUSED(info);
	LOG_INF("PA sync established");
	k_sem_give(&sem_pa_synced);
}

static void pa_term_cb(struct bt_le_per_adv_sync *sync,
		       const struct bt_le_per_adv_sync_term_info *info)
{
	ARG_UNUSED(sync);
	ARG_UNUSED(info);
	LOG_WRN("PA sync terminated");
}

static void pa_biginfo_cb(struct bt_le_per_adv_sync *sync,
			  const struct bt_iso_biginfo *biginfo)
{
	ARG_UNUSED(sync);

	if (biginfo->addr != NULL) {
		bt_addr_le_copy(&cached_biginfo_addr, biginfo->addr);
	}
	const bool first_ever = (cached_biginfo.num_bis == 0U);
	cached_biginfo = *biginfo;
	cached_biginfo.addr = &cached_biginfo_addr;

	/* BIGInfo cb comes every PA interval. Only log
	 * the first one so we don't drown the shell UART. */
	if (first_ever) {
		LOG_INF("BIGInfo: num_bis=%u nse=%u iso_int=%u bn=%u irc=%u pto=%u "
			"max_pdu=%u max_sdu=%u framing=%u enc=%u",
			biginfo->num_bis, biginfo->sub_evt_count, biginfo->iso_interval,
			biginfo->burst_number, biginfo->rep_count, biginfo->offset,
			biginfo->max_pdu, biginfo->max_sdu, biginfo->framing,
			biginfo->encryption);
	}

	k_sem_give(&sem_biginfo);
}

static struct bt_le_per_adv_sync_cb pa_cb = {
	.synced  = pa_synced_cb,
	.term    = pa_term_cb,
	.biginfo = pa_biginfo_cb,
};

/* ----- Public API ----- */

int sniffer_bis_sink_init(void)
{
	for (int i = 0; i < CONFIG_BT_ISO_MAX_CHAN; i++) {
		bis_qos[i].rx        = &bis_rx_qos[i];
		bis_iso_chan[i].ops  = &iso_ops;
		bis_iso_chan[i].qos  = &bis_qos[i];
		bis_ptrs[i]          = &bis_iso_chan[i];
		handles_for_bis[i]   = SNIFFER_BIS_HANDLE_BASE + i;
	}
	bt_le_per_adv_sync_cb_register(&pa_cb);
	return 0;
}

int sniffer_bis_sink_start(const struct sniffer_candidate *cand)
{
	int err;

	if (big != NULL || pa != NULL) {
		return -EBUSY;
	}

	if (big_sync_is_active()) {
		LOG_ERR("attack sync owns the BIG sync - `bison unsync` or "
			"`bisquit stop` first");
		return -EBUSY;
	}
	if (clone_is_active()) {
		LOG_ERR("clone owns the radio - `clone stop` first");
		return -EBUSY;
	}

	if (!sniffer_scan_is_active()) {
		err = sniffer_scan_start();
		if (err && err != -EALREADY) {
			return err;
		}
	}

	k_sem_reset(&sem_pa_synced);
	k_sem_reset(&sem_biginfo);
	k_sem_reset(&sem_bis_up);
	k_sem_reset(&sem_bis_lost);
	connected_count = 0U;

	struct bt_le_per_adv_sync_param sp = {0};
	bt_addr_le_copy(&sp.addr, &cand->addr);
	sp.sid     = cand->sid;
	sp.options = 0U;
	sp.skip    = 0U;

	uint32_t interval_us = cand->pa_interval_us ? cand->pa_interval_us : 100000U;
	uint32_t timeout_10ms = (interval_us * PA_RETRY_COUNT) / (10U * USEC_PER_MSEC);
	sp.timeout = (uint16_t)CLAMP(timeout_10ms, 10U, 0xFFFFU);

	err = bt_le_per_adv_sync_create(&sp, &pa);
	if (err) {
		LOG_ERR("bt_le_per_adv_sync_create: %d", err);
		return err;
	}

	err = k_sem_take(&sem_pa_synced, K_MSEC(PA_SYNCED_TIMEOUT_MS));
	if (err) {
		LOG_ERR("PA sync timeout");
		goto fail_after_pa;
	}

	err = k_sem_take(&sem_biginfo, K_MSEC(BIGINFO_TIMEOUT_MS));
	if (err) {
		LOG_ERR("BIGInfo timeout");
		goto fail_after_pa;
	}

	(void)sniffer_scan_stop();

	uint8_t num_bis = MIN(cached_biginfo.num_bis, CONFIG_BT_ISO_MAX_CHAN);
	if (num_bis == 0U) {
		LOG_ERR("BIG has zero BIS");
		err = -EINVAL;
		goto fail_after_pa;
	}

	uint8_t sync_num_bis = sniffer_bis_sink_get_single_bis() ? 1U : num_bis;
	uint32_t bitfield = 0U;
	for (uint8_t i = 0; i < sync_num_bis; i++) {
		bitfield |= BT_ISO_BIS_INDEX_BIT(i + 1U);
	}

	struct bt_iso_big_sync_param sync_param = {
		.bis_channels = bis_ptrs,
		.num_bis      = sync_num_bis,
		.bis_bitfield = bitfield,
		.mse          = BT_ISO_SYNC_MSE_ANY,
		.sync_timeout = 100U, /* 100 * 10 ms = 1 s */
		.encryption   = cached_biginfo.encryption,
	};

	const bool raw_flag = sniffer_tap_raw_enc_get();
	const bool active_raw_enc = raw_flag && cached_biginfo.encryption;

	if (cached_biginfo.encryption) {
		if (cand->bcode_len > 0U) {
			size_t copy = MIN((size_t)cand->bcode_len,
					  sizeof(sync_param.bcode));

			memcpy(sync_param.bcode, cand->bcode, copy);
		} else if (active_raw_enc) {
			/* Lie to Zephyr's ULL: pass encryption=0 so
			 * ll_big_create_sync skips the h7/h6 GLTK derivation
			 * (which would run on the zero-init bcode and later
			 * assertion-fail in isr_rx on MIC mismatch). Zephyr
			 * configures the radio for plain RX; the LLL widens
			 * the DMA window by PDU_MIC_SIZE when
			 * sniffer_tap_raw_enc_get() is on, so we still
			 * capture ciphertext + MIC.
			 */
			sync_param.encryption = 0U;
			LOG_INF("raw-enc mode: BIG is encrypted, forwarding "
				"ciphertext (no MIC check)");
		} else {
			LOG_ERR("encrypted BIG requires either "
				"`scan bcode <target> <hex>` or `sniff raw on`");
			err = -EACCES;
			goto fail_after_pa;
		}
	}

	err = bt_iso_big_sync(pa, &sync_param, &big);
	if (err) {
		LOG_ERR("bt_iso_big_sync: %d", err);
		goto fail_after_pa;
	}

	err = k_sem_take(&sem_bis_up, K_MSEC(BIS_UP_TIMEOUT_MS));
	if (err) {
		LOG_ERR("no BIS came up in %d ms", BIS_UP_TIMEOUT_MS);
		bt_iso_big_terminate(big);
		big = NULL;
		goto fail_after_pa;
	}

	return 0;

fail_after_pa:
	if (pa != NULL) {
		bt_le_per_adv_sync_delete(pa);
		pa = NULL;
	}
	return err;
}

int sniffer_bis_sink_stop(void)
{
	if (big != NULL) {
		bt_iso_big_terminate(big);
		big = NULL;
	}
	if (pa != NULL) {
		bt_le_per_adv_sync_delete(pa);
		pa = NULL;
	}
	connected_count = 0U;
	return 0;
}

bool sniffer_bis_sink_is_active(void)
{
	return big != NULL;
}

void sniffer_bis_sink_status(char *out, size_t out_sz)
{
	/* iso_interval is in units of 1.25 ms per Core spec; convert. */
	uint32_t iso_us = (uint32_t)cached_biginfo.iso_interval * 1250U;
	snprintk(out, out_sz,
		 "pa=%s big=%s bis_up=%u num_bis=%u iso_interval=%u.%03u ms "
		 "enc=%u framing=%u phy=%u max_sdu=%u",
		 pa != NULL ? "yes" : "no",
		 big != NULL ? "yes" : "no",
		 connected_count,
		 cached_biginfo.num_bis,
		 iso_us / 1000U, iso_us % 1000U,
		 cached_biginfo.encryption,
		 cached_biginfo.framing,
		 cached_biginfo.phy,
		 cached_biginfo.max_sdu);
}
