#include "big_sync.h"

#include "sniff/bis_sink.h"

#include "clone.h"

#include "bison_lll_hijack.h"

#include "sniffer_tap.h"

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net_buf.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci_types.h>
#include <zephyr/bluetooth/iso.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(big_sync, LOG_LEVEL_INF);

#define PA_SYNCED_TIMEOUT_MS   2000
#define BIGINFO_TIMEOUT_MS     3000
#define BIS_UP_TIMEOUT_MS     10000
#define PA_RETRY_COUNT            6

/* We always sync exactly one BIS */
#define BIG_SYNC_NUM_BIS 1U

static struct bt_iso_chan_io_qos rx_qos;
static struct bt_iso_chan_qos    qos;
static struct bt_iso_chan        iso_chan;
static struct bt_iso_chan       *iso_chans[BIG_SYNC_NUM_BIS];

static struct bt_le_per_adv_sync *pa;
static struct bt_iso_big         *big;

static struct bt_iso_biginfo cached_biginfo;
static bt_addr_le_t          cached_biginfo_addr;

static uint8_t  pa_payload[BIG_SYNC_PA_PAYLOAD_MAX];
static size_t   pa_payload_len;
static bool     pa_payload_valid;
static K_SEM_DEFINE(sem_pa_payload, 0, 1);

static uint8_t bis_last_disc_reason;

static K_SEM_DEFINE(sem_pa_synced, 0, 1);
static K_SEM_DEFINE(sem_biginfo,   0, 1);
static K_SEM_DEFINE(sem_bis_up,    0, BIG_SYNC_NUM_BIS);

static void iso_recv(struct bt_iso_chan *chan,
		     const struct bt_iso_recv_info *info,
		     struct net_buf *buf)
{
	ARG_UNUSED(chan);
	ARG_UNUSED(info);
	ARG_UNUSED(buf);
}

static void iso_connected(struct bt_iso_chan *chan)
{
	ARG_UNUSED(chan);
	bis_last_disc_reason = 0U;
	LOG_INF("big_sync: BIS 1 connected");
	k_sem_give(&sem_bis_up);
}

static void iso_disconnected(struct bt_iso_chan *chan, uint8_t reason)
{
	ARG_UNUSED(chan);
	bis_last_disc_reason = reason ? reason : 0xFFU;
	LOG_INF("big_sync: BIS 1 disconnected (reason 0x%02x)", reason);
	k_sem_give(&sem_bis_up);
}

static struct bt_iso_chan_ops iso_ops = {
	.recv         = iso_recv,
	.connected    = iso_connected,
	.disconnected = iso_disconnected,
};

static void pa_synced_cb(struct bt_le_per_adv_sync *sync,
			 struct bt_le_per_adv_sync_synced_info *info)
{
	ARG_UNUSED(sync);
	ARG_UNUSED(info);
	LOG_INF("big_sync: PA sync established");
	k_sem_give(&sem_pa_synced);
}

static void pa_term_cb(struct bt_le_per_adv_sync *sync,
		       const struct bt_le_per_adv_sync_term_info *info)
{
	ARG_UNUSED(sync);
	ARG_UNUSED(info);
	LOG_WRN("big_sync: PA sync terminated");
}

static void pa_biginfo_cb(struct bt_le_per_adv_sync *sync,
			  const struct bt_iso_biginfo *biginfo)
{
	ARG_UNUSED(sync);
	if (biginfo->addr != NULL) {
		bt_addr_le_copy(&cached_biginfo_addr, biginfo->addr);
	}
	cached_biginfo = *biginfo;
	cached_biginfo.addr = &cached_biginfo_addr;
	k_sem_give(&sem_biginfo);
}

static void pa_recv_cb(struct bt_le_per_adv_sync *sync,
		       const struct bt_le_per_adv_sync_recv_info *info,
		       struct net_buf_simple *buf)
{
	ARG_UNUSED(sync);
	ARG_UNUSED(info);

	if (pa_payload_valid) {
		return; /* already captured */
	}
	if (buf->len > sizeof(pa_payload)) {
		LOG_WRN("big_sync: PA payload %u > %u, truncating",
			buf->len, (unsigned)sizeof(pa_payload));
		pa_payload_len = sizeof(pa_payload);
	} else {
		pa_payload_len = buf->len;
	}
	memcpy(pa_payload, buf->data, pa_payload_len);
	pa_payload_valid = true;
	k_sem_give(&sem_pa_payload);
}

static struct bt_le_per_adv_sync_cb pa_cb = {
	.synced  = pa_synced_cb,
	.term    = pa_term_cb,
	.biginfo = pa_biginfo_cb,
	.recv    = pa_recv_cb,
};

/* ----- Public API ----- */

int big_sync_init(void)
{
	qos.rx        = &rx_qos;
	iso_chan.ops  = &iso_ops;
	iso_chan.qos  = &qos;
	iso_chans[0]  = &iso_chan;
	bt_le_per_adv_sync_cb_register(&pa_cb);
	return 0;
}

#define BIG_SYNC_TRACE(sh, ...)                          \
	do {                                             \
		if ((sh) != NULL) {                      \
			shell_print((sh), __VA_ARGS__);  \
		} else {                                 \
			LOG_INF(__VA_ARGS__);            \
		}                                        \
	} while (0)

static int pa_sync_and_biginfo(const struct sniffer_candidate *cand,
			       const struct shell *sh)
{
	int err;

	if (!sniffer_scan_is_active()) {
		BIG_SYNC_TRACE(sh, "big_sync: starting discovery scan");
		err = sniffer_scan_start();
		if (err && err != -EALREADY) {
			BIG_SYNC_TRACE(sh, "big_sync: scan_start failed: %d", err);
			return err;
		}
	}

	k_sem_reset(&sem_pa_synced);
	k_sem_reset(&sem_biginfo);
	k_sem_reset(&sem_pa_payload);
	pa_payload_valid = false;
	pa_payload_len   = 0U;

	struct bt_le_per_adv_sync_param sp = {0};

	bt_addr_le_copy(&sp.addr, &cand->addr);
	sp.sid     = cand->sid;
	sp.options = 0U;
	sp.skip    = 0U;

	uint32_t interval_us = cand->pa_interval_us ? cand->pa_interval_us : 100000U;
	uint32_t timeout_10ms = (interval_us * PA_RETRY_COUNT) / (10U * USEC_PER_MSEC);

	sp.timeout = (uint16_t)CLAMP(timeout_10ms, 10U, 0xFFFFU);

	BIG_SYNC_TRACE(sh, "big_sync: creating PA sync (sid=%u timeout=%u)",
		       sp.sid, sp.timeout);

	err = bt_le_per_adv_sync_create(&sp, &pa);
	if (err) {
		BIG_SYNC_TRACE(sh, "big_sync: bt_le_per_adv_sync_create: %d", err);
		return err;
	}

	BIG_SYNC_TRACE(sh, "big_sync: waiting for PA synced event (up to %u ms)",
		       PA_SYNCED_TIMEOUT_MS);

	err = k_sem_take(&sem_pa_synced, K_MSEC(PA_SYNCED_TIMEOUT_MS));
	if (err) {
		BIG_SYNC_TRACE(sh, "big_sync: PA sync TIMEOUT");
		goto fail;
	}

	BIG_SYNC_TRACE(sh, "big_sync: PA synced, waiting for BIGInfo (up to %u ms)",
		       BIGINFO_TIMEOUT_MS);

	err = k_sem_take(&sem_biginfo, K_MSEC(BIGINFO_TIMEOUT_MS));
	if (err) {
		BIG_SYNC_TRACE(sh, "big_sync: BIGInfo TIMEOUT");
		goto fail;
	}

	BIG_SYNC_TRACE(sh, "big_sync: BIGInfo OK (num_bis=%u iso_int=%u enc=%u)",
		       cached_biginfo.num_bis, cached_biginfo.iso_interval,
		       cached_biginfo.encryption);

	return 0;

fail:
	bt_le_per_adv_sync_delete(pa);
	pa = NULL;
	return err;
}

int big_sync_start(const struct sniffer_candidate *cand,
		   const uint8_t *bcode, size_t bcode_len,
		   const struct shell *sh)
{
	int err;

	BIG_SYNC_TRACE(sh, "big_sync: entered start");

	if (big != NULL || pa != NULL) {
		BIG_SYNC_TRACE(sh, "big_sync: EBUSY - big or pa non-NULL");
		return -EBUSY;
	}

	if (sniffer_bis_sink_is_active()) {
		BIG_SYNC_TRACE(sh, "big_sync: EBUSY - `sniff start` owns the BIG sync");
		return -EBUSY;
	}
	if (clone_is_active()) {
		BIG_SYNC_TRACE(sh, "big_sync: EBUSY - `clone start` owns the radio");
		return -EBUSY;
	}

	k_sem_reset(&sem_bis_up);
	bis_last_disc_reason = 0U;

	err = pa_sync_and_biginfo(cand, sh);
	if (err) {
		return err;
	}

	(void)sniffer_scan_stop();

	if (cached_biginfo.num_bis == 0U) {
		BIG_SYNC_TRACE(sh, "big_sync: BIG has zero BIS");
		err = -EINVAL;
		goto fail_after_pa;
	}

	struct bt_iso_big_sync_param sync_param = {
		.bis_channels = iso_chans,
		.num_bis      = BIG_SYNC_NUM_BIS,
		.bis_bitfield = BT_ISO_BIS_INDEX_BIT(1U),
		.mse          = BT_ISO_SYNC_MSE_ANY,
		.sync_timeout = 100U, /* 100 * 10 ms = 1 s */
		.encryption   = cached_biginfo.encryption,
	};

	if (cached_biginfo.encryption) {
		if (bcode != NULL && bcode_len != 0U) {
			size_t copy = MIN(bcode_len, sizeof(sync_param.bcode));

			memcpy(sync_param.bcode, bcode, copy);
		} else {
			if (!bison_lll_hijack_bisquit_bypass_get()) {
				BIG_SYNC_TRACE(sh,
					"big_sync: encrypted BIG - set `scan "
					"bcode <target> <hex>` first (or use "
					"`bisquit start` which turns on the "
					"MIC-fail bypass)");
				err = -EACCES;
				goto fail_after_pa;
			}
			sync_param.encryption = 0U;
			/* No decryptable BIG_CHANNEL_MAP_IND without the bcode:
			 * follow channel-map updates via the cleartext BIGInfo
			 * so we don't desync when the sender re-maps channels. */
			sniffer_tap_chm_follow_set(true);
			BIG_SYNC_TRACE(sh, "big_sync: encrypted BIG, bisquit "
					   "bypass on - forwarding ciphertext "
					   "(no MIC check), chmfollow on");
		}
	}

	BIG_SYNC_TRACE(sh, "big_sync: calling bt_iso_big_sync (num_bis=%u enc=%u)",
		       sync_param.num_bis, sync_param.encryption);

	err = bt_iso_big_sync(pa, &sync_param, &big);
	if (err) {
		BIG_SYNC_TRACE(sh, "big_sync: bt_iso_big_sync failed: %d", err);
		goto fail_after_pa;
	}

	BIG_SYNC_TRACE(sh, "big_sync: bt_iso_big_sync OK, waiting for BIS up "
			   "(up to %u ms)", BIS_UP_TIMEOUT_MS);

	err = k_sem_take(&sem_bis_up, K_MSEC(BIS_UP_TIMEOUT_MS));
	if (err) {
		BIG_SYNC_TRACE(sh, "big_sync: BIS didn't come up in %d ms "
				   "(no callback fired - LL never emitted a "
				   "sync-established event)", BIS_UP_TIMEOUT_MS);
		bt_iso_big_terminate(big);
		big = NULL;
		goto fail_after_pa;
	}

	if (bis_last_disc_reason != 0U) {
		BIG_SYNC_TRACE(sh, "big_sync: LL rejected sync (disconnect "
				   "reason 0x%02x)", bis_last_disc_reason);
		bt_iso_big_terminate(big);
		big = NULL;
		err = -ECONNREFUSED;
		goto fail_after_pa;
	}

	BIG_SYNC_TRACE(sh, "big_sync: BIS 1 up - snapshot is populating");
	return 0;

fail_after_pa:
	if (pa != NULL) {
		bt_le_per_adv_sync_delete(pa);
		pa = NULL;
	}
	return err;
}

int big_sync_stop(void)
{
	if (big != NULL) {
		bt_iso_big_terminate(big);
		big = NULL;
	}
	if (pa != NULL) {
		bt_le_per_adv_sync_delete(pa);
		pa = NULL;
	}
	return 0;
}

bool big_sync_is_active(void)
{
	return big != NULL;
}

void big_sync_status(char *out, size_t out_sz)
{
	uint32_t iso_us = (uint32_t)cached_biginfo.iso_interval * 1250U;

	snprintk(out, out_sz,
		 "pa=%s big=%s num_bis_in_big=%u iso_interval=%u.%03u ms "
		 "enc=%u framing=%u phy=%u max_pdu=%u",
		 pa != NULL ? "yes" : "no",
		 big != NULL ? "yes" : "no",
		 cached_biginfo.num_bis,
		 iso_us / 1000U, iso_us % 1000U,
		 cached_biginfo.encryption,
		 cached_biginfo.framing,
		 cached_biginfo.phy,
		 cached_biginfo.max_pdu);
}

int big_sync_biginfo_only(const struct sniffer_candidate *cand,
			  struct bt_iso_biginfo *out_biginfo,
			  uint8_t *out_pa_payload,
			  size_t *out_pa_payload_len,
			  const struct shell *sh)
{
	int err;

	if (pa != NULL || big != NULL) {
		BIG_SYNC_TRACE(sh, "big_sync: EBUSY - existing sync in flight");
		return -EBUSY;
	}

	if (sniffer_bis_sink_is_active()) {
		BIG_SYNC_TRACE(sh, "big_sync: EBUSY - `sniff start` owns the "
				   "PA sync path");
		return -EBUSY;
	}
	if (clone_is_active()) {
		BIG_SYNC_TRACE(sh, "big_sync: EBUSY - `clone start` owns the "
				   "radio");
		return -EBUSY;
	}

	err = pa_sync_and_biginfo(cand, sh);
	if (err) {
		return err;
	}

	(void)sniffer_scan_stop();

	if (out_biginfo != NULL) {
		*out_biginfo = cached_biginfo;
		out_biginfo->addr = &cached_biginfo_addr;
	}

	if (out_pa_payload != NULL && out_pa_payload_len != NULL) {
		BIG_SYNC_TRACE(sh, "big_sync: waiting for PA payload "
				   "(up to 500 ms)");

		err = k_sem_take(&sem_pa_payload, K_MSEC(500));
		if (err) {
			BIG_SYNC_TRACE(sh, "big_sync: PA payload TIMEOUT "
					   "(source might broadcast BIGInfo-only, "
					   "no BASE)");
			*out_pa_payload_len = 0U;
		} else {
			memcpy(out_pa_payload, pa_payload, pa_payload_len);
			*out_pa_payload_len = pa_payload_len;
			BIG_SYNC_TRACE(sh, "big_sync: captured PA payload "
					   "(%u bytes)",
				       (unsigned)pa_payload_len);
		}
	}

	bt_le_per_adv_sync_delete(pa);
	pa = NULL;
	return 0;
}
