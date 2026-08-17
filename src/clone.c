/*
 *  WIP
 */

#include "clone.h"
#include "big_sync.h"

#include "sniff/bis_sink.h"

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net_buf.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/gap.h>
#include <zephyr/bluetooth/iso.h>
#include <zephyr/bluetooth/hci_types.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(clone, LOG_LEVEL_INF);

#define AHT_CLONE_MAX_BIS 4U /* matches typical CONFIG_BT_ISO_MAX_CHAN */

BUILD_ASSERT(CONFIG_BT_ISO_MAX_CHAN >= AHT_CLONE_MAX_BIS,
	     "clone assumes at least AHT_CLONE_MAX_BIS ISO channels available");

static struct bt_le_ext_adv *adv;
static struct bt_iso_big    *big;
static bool                  active;

static struct bt_iso_chan_io_qos iso_tx_qos[AHT_CLONE_MAX_BIS];
static struct bt_iso_chan_qos    iso_qos[AHT_CLONE_MAX_BIS];
static struct bt_iso_chan        iso_chans[AHT_CLONE_MAX_BIS];
static struct bt_iso_chan       *iso_chan_ptrs[AHT_CLONE_MAX_BIS];
static uint8_t                   iso_num_bis;

static K_SEM_DEFINE(sem_big_up, 0, AHT_CLONE_MAX_BIS);

static uint16_t seq_num[AHT_CLONE_MAX_BIS];

#define AHT_CLONE_MAX_SDU_LEN 251U
static uint8_t  sdu_fill[AHT_CLONE_MAX_SDU_LEN];
static uint16_t sdu_len;

static uint32_t sdu_interval_us;

NET_BUF_POOL_FIXED_DEFINE(clone_tx_pool, AHT_CLONE_MAX_BIS,
			  BT_ISO_SDU_BUF_SIZE(AHT_CLONE_MAX_SDU_LEN),
			  CONFIG_BT_CONN_TX_USER_DATA_SIZE, NULL);

static void iso_connected(struct bt_iso_chan *chan)
{
	const struct bt_iso_chan_path hci_path = {
		.pid    = BT_ISO_DATA_PATH_HCI,
		.format = BT_HCI_CODING_FORMAT_TRANSPARENT,
	};
	ptrdiff_t idx = chan - &iso_chans[0];
	int err;

	if (idx < 0 || idx >= AHT_CLONE_MAX_BIS) {
		return;
	}

	err = bt_iso_setup_data_path(chan, BT_HCI_DATAPATH_DIR_HOST_TO_CTLR,
				     &hci_path);
	if (err) {
		LOG_ERR("clone: BIS %ld data-path setup failed: %d",
			(long)(idx + 1), err);
	}

	LOG_INF("clone: BIS %ld connected", (long)(idx + 1));
	seq_num[idx] = 0U;
	k_sem_give(&sem_big_up);
}

static void iso_disconnected(struct bt_iso_chan *chan, uint8_t reason)
{
	ptrdiff_t idx = chan - &iso_chans[0];

	LOG_INF("clone: BIS %ld disconnected (reason 0x%02x)",
		(long)(idx + 1), reason);
}

static void iso_sent(struct bt_iso_chan *chan)
{
	ARG_UNUSED(chan);
}

static struct bt_iso_chan_ops iso_ops = {
	.connected    = iso_connected,
	.disconnected = iso_disconnected,
	.sent         = iso_sent,
};


static void clone_tx_work_handler(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(clone_tx_work, clone_tx_work_handler);

static int64_t next_target_us;

static void clone_reschedule_next(void)
{
	int64_t now_us = k_uptime_get() * 1000LL;
	int64_t delay_us;

	next_target_us += sdu_interval_us;
	delay_us = next_target_us - now_us;
	if (delay_us < 0) {
		next_target_us = now_us + sdu_interval_us;
		delay_us = sdu_interval_us;
	}
	(void)k_work_reschedule(&clone_tx_work, K_USEC(delay_us));
}

static void clone_tx_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	if (!active) {
		return;
	}

	for (uint8_t i = 0U; i < iso_num_bis; i++) {
		struct net_buf *buf;
		int err;

		buf = net_buf_alloc(&clone_tx_pool, K_NO_WAIT);
		if (buf == NULL) {
			/* Pool exhausted, LL is behind on TX_DONE. Skip
			 * this SDU on this BIS rather than block the
			 * whole workqueue. */
			continue;
		}
		net_buf_reserve(buf, BT_ISO_CHAN_SEND_RESERVE);
		net_buf_add_mem(buf, sdu_fill, sdu_len);

		err = bt_iso_chan_send(&iso_chans[i], buf, seq_num[i]);
		if (err < 0) {
			LOG_WRN("clone: bt_iso_chan_send BIS %u seq %u: %d",
				(unsigned)(i + 1U), seq_num[i], err);
			net_buf_unref(buf);
			continue;
		}
		seq_num[i]++;
	}

	clone_reschedule_next();
}

int clone_init(void)
{
	for (uint8_t i = 0U; i < AHT_CLONE_MAX_BIS; i++) {
		iso_qos[i].tx        = &iso_tx_qos[i];
		iso_chans[i].ops     = &iso_ops;
		iso_chans[i].qos     = &iso_qos[i];
		iso_chan_ptrs[i]     = &iso_chans[i];
	}
	return 0;
}

#define CLONE_TRACE(sh, ...)                              \
	do {                                              \
		if ((sh) != NULL) {                       \
			shell_print((sh), __VA_ARGS__);   \
		} else {                                  \
			LOG_INF(__VA_ARGS__);             \
		}                                         \
	} while (0)

static uint8_t pa_payload_buf[BIG_SYNC_PA_PAYLOAD_MAX];
static size_t  pa_payload_buf_len;

#define CLONE_MAX_PA_AD_ENTRIES 8
static struct bt_data pa_ad_entries[CLONE_MAX_PA_AD_ENTRIES];
static size_t         pa_ad_entries_count;

static bool pa_ad_parser(struct bt_data *data, void *user_data)
{
	ARG_UNUSED(user_data);

	if (pa_ad_entries_count >= CLONE_MAX_PA_AD_ENTRIES) {
		return false;
	}
	pa_ad_entries[pa_ad_entries_count++] = *data;
	return true;
}

int clone_start(const struct sniffer_candidate *cand, const struct shell *sh)
{
	struct bt_iso_biginfo bi = {0};
	int err;

	if (active) {
		CLONE_TRACE(sh, "clone: already running, `clone stop` first");
		return -EBUSY;
	}

	if (sniffer_bis_sink_is_active()) {
		CLONE_TRACE(sh, "clone: EBUSY, `sniff stop` first");
		return -EBUSY;
	}
	if (big_sync_is_active()) {
		CLONE_TRACE(sh, "clone: EBUSY, `bison unsync` / `bisquit stop` first");
		return -EBUSY;
	}

	CLONE_TRACE(sh, "clone: fetching BIGInfo + PA payload from target");

	pa_payload_buf_len = 0U;
	err = big_sync_biginfo_only(cand, &bi,
				    pa_payload_buf, &pa_payload_buf_len, sh);
	if (err) {
		CLONE_TRACE(sh, "clone: BIGInfo fetch failed: %d", err);
		return err;
	}

	if (bi.num_bis == 0U || bi.num_bis > AHT_CLONE_MAX_BIS) {
		CLONE_TRACE(sh, "clone: unsupported num_bis=%u", bi.num_bis);
		return -EINVAL;
	}

	if (bi.max_sdu == 0U || bi.max_sdu > AHT_CLONE_MAX_SDU_LEN) {
		CLONE_TRACE(sh, "clone: unsupported max_sdu=%u", bi.max_sdu);
		return -EINVAL;
	}
	if (bi.encryption && cand->bcode_len == 0U) {
		CLONE_TRACE(sh, "clone: target is encrypted; set the "
				"broadcast_code via `scan bcode <target> <hex>` first");
		return -EACCES;
	}

	/* BIGInfo iso_interval is 1.25 ms. Candidate. We halve the PA interval
	 * so scanners see us at twice the rate ??
	 * Not sure if that works/make sense
	 */
	uint32_t src_pa_us = cand->pa_interval_us ? cand->pa_interval_us : 100000U;
	// uint32_t our_pa_us = src_pa_us / 2U;
	uint32_t our_pa_ms = our_pa_us / 1000U;

	if (our_pa_ms < 10U) {
		our_pa_ms = 10U;
	}

	uint16_t ext_adv_ms = (our_pa_ms > 20U) ? (our_pa_ms - 10U) : our_pa_ms;

	CLONE_TRACE(sh, "clone: BIGInfo num_bis=%u iso_int=%u bn=%u irc=%u "
			"pto=%u max_pdu=%u max_sdu=%u sdu_int_us=%u phy=%u "
			"framing=%u enc=%u",
		    bi.num_bis, bi.iso_interval, bi.burst_number, bi.rep_count,
		    bi.offset, bi.max_pdu, bi.max_sdu, bi.sdu_interval,
		    bi.phy, bi.framing, bi.encryption);
	CLONE_TRACE(sh, "clone: our_pa_ms=%u ext_adv_ms=%u",
		    our_pa_ms, ext_adv_ms);

	const struct bt_le_adv_param *ext_adv_param = BT_LE_ADV_PARAM(
		BT_LE_ADV_OPT_EXT_ADV,
		BT_GAP_MS_TO_ADV_INTERVAL(ext_adv_ms),
		BT_GAP_MS_TO_ADV_INTERVAL(ext_adv_ms), NULL);

	err = bt_le_ext_adv_create(ext_adv_param, NULL, &adv);
	if (err) {
		CLONE_TRACE(sh, "clone: bt_le_ext_adv_create: %d", err);
		return err;
	}

	static uint8_t baa_data[2 + 3];
	uint32_t bid = cand->has_broadcast_id ? cand->broadcast_id : 0x000000U;

	sys_put_le16(0x1852U, baa_data);
	sys_put_le24(bid, baa_data + 2);

	size_t name_len = strnlen(cand->name, SNIFFER_CAND_NAME_MAX - 1);
	struct bt_data ext_ad[2] = {
		{
			.type = BT_DATA_SVC_DATA16,
			.data_len = sizeof(baa_data),
			.data = baa_data,
		},
		{
			.type = BT_DATA_BROADCAST_NAME,
			.data_len = (uint8_t)name_len,
			.data = (const uint8_t *)cand->name,
		},
	};
	size_t ext_ad_count = (name_len > 0U) ? 2U : 1U;

	err = bt_le_ext_adv_set_data(adv, ext_ad, ext_ad_count, NULL, 0);
	if (err) {
		CLONE_TRACE(sh, "clone: bt_le_ext_adv_set_data: %d", err);
		goto fail_delete_adv;
	}

	struct bt_le_per_adv_param per_adv_param = {
		.interval_min = BT_GAP_MS_TO_PER_ADV_INTERVAL(our_pa_ms),
		.interval_max = BT_GAP_MS_TO_PER_ADV_INTERVAL(our_pa_ms),
		.options      = BT_LE_PER_ADV_OPT_NONE,
	};

	err = bt_le_per_adv_set_param(adv, &per_adv_param);
	if (err) {
		CLONE_TRACE(sh, "clone: bt_le_per_adv_set_param: %d", err);
		goto fail_delete_adv;
	}

	pa_ad_entries_count = 0U;
	if (pa_payload_buf_len > 0U) {
		struct net_buf_simple pa_buf;

		net_buf_simple_init_with_data(&pa_buf, pa_payload_buf,
					      pa_payload_buf_len);
		bt_data_parse(&pa_buf, pa_ad_parser, NULL);

		if (pa_ad_entries_count > 0U) {
			err = bt_le_per_adv_set_data(adv, pa_ad_entries,
						     pa_ad_entries_count);
			if (err) {
				CLONE_TRACE(sh, "clone: bt_le_per_adv_set_data: %d "
						"(source PA has %u entries, %u bytes)",
					    err,
					    (unsigned)pa_ad_entries_count,
					    (unsigned)pa_payload_buf_len);
				goto fail_delete_adv;
			}
			CLONE_TRACE(sh, "clone: replicated source PA payload "
					"(%u entries, %u bytes)",
				    (unsigned)pa_ad_entries_count,
				    (unsigned)pa_payload_buf_len);
		}
	} else {
		CLONE_TRACE(sh, "clone: source has no PA payload. clone "
				"broadcasts BIGInfo-only PA (some receivers may not discover)");
	}

	err = bt_le_per_adv_start(adv);
	if (err) {
		CLONE_TRACE(sh, "clone: bt_le_per_adv_start: %d", err);
		goto fail_delete_adv;
	}

	err = bt_le_ext_adv_start(adv, BT_LE_EXT_ADV_START_DEFAULT);
	if (err) {
		CLONE_TRACE(sh, "clone: bt_le_ext_adv_start: %d", err);
		goto fail_stop_per_adv;
	}

	for (uint8_t i = 0U; i < bi.num_bis; i++) {
		iso_tx_qos[i].sdu          = bi.max_sdu;
		iso_tx_qos[i].phy          = bi.phy;
		iso_tx_qos[i].rtn          = 0U;
		iso_tx_qos[i].max_pdu      = bi.max_pdu;
		iso_tx_qos[i].burst_number = bi.burst_number;
		iso_qos[i].num_subevents   = bi.sub_evt_count;
	}
	iso_num_bis = bi.num_bis;

	struct bt_iso_big_create_param big_param = {
		.bis_channels  = iso_chan_ptrs,
		.num_bis       = bi.num_bis,
		.interval      = bi.sdu_interval,
		.latency       = 0U,
		.packing       = BT_ISO_PACKING_INTERLEAVED,
		.framing       = bi.framing,
		.encryption    = bi.encryption,
		.iso_interval  = bi.iso_interval,
		.irc           = bi.rep_count,
		.pto           = bi.offset,
	};

	if (bi.encryption) {
		size_t copy = MIN((size_t)cand->bcode_len,
				  sizeof(big_param.bcode));

		memcpy(big_param.bcode, cand->bcode, copy);
	}

	k_sem_reset(&sem_big_up);

	err = bt_iso_big_create(adv, &big_param, &big);
	if (err) {
		CLONE_TRACE(sh, "clone: bt_iso_big_create: %d", err);
		goto fail_stop_ext_adv;
	}

	CLONE_TRACE(sh, "clone: waiting for BIG BIS(es) to come up");

	for (uint8_t i = 0U; i < bi.num_bis; i++) {
		err = k_sem_take(&sem_big_up, K_SECONDS(5));
		if (err) {
			CLONE_TRACE(sh, "clone: BIS %u didn't come up",
				    (unsigned)(i + 1U));
			bt_iso_big_terminate(big);
			big = NULL;
			goto fail_stop_ext_adv;
		}
	}


	sdu_len = bi.max_sdu;
	sdu_interval_us = bi.sdu_interval ? bi.sdu_interval : 10000U;
	memset(sdu_fill, 0x41, sizeof(sdu_fill));

	active = true;
	next_target_us = k_uptime_get() * 1000LL;
	(void)k_work_reschedule(&clone_tx_work, K_NO_WAIT);

	CLONE_TRACE(sh, "clone: broadcasting num_bis=%u sdu_len=%u "
			"sdu_int_us=%u pa_ms=%u",
		    iso_num_bis, sdu_len, sdu_interval_us, our_pa_ms);
	return 0;

fail_stop_ext_adv:
	(void)bt_le_ext_adv_stop(adv);
fail_stop_per_adv:
	(void)bt_le_per_adv_stop(adv);
fail_delete_adv:
	(void)bt_le_ext_adv_delete(adv);
	adv = NULL;
	return err;
}

int clone_stop(void)
{
	active = false;
	(void)k_work_cancel_delayable(&clone_tx_work);

	if (big != NULL) {
		(void)bt_iso_big_terminate(big);
		big = NULL;
	}
	if (adv != NULL) {
		(void)bt_le_ext_adv_stop(adv);
		(void)bt_le_per_adv_stop(adv);
		(void)bt_le_ext_adv_delete(adv);
		adv = NULL;
	}
	return 0;
}

bool clone_is_active(void)
{
	return active;
}

void clone_status(char *out, size_t out_sz)
{
	snprintk(out, out_sz,
		 "adv=%s big=%s num_bis=%u sdu_len=%u sdu_int_us=%u",
		 adv != NULL ? "yes" : "no",
		 big != NULL ? "yes" : "no",
		 iso_num_bis, sdu_len, sdu_interval_us);
}
