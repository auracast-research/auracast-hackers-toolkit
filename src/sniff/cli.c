#include "cli.h"
#include "scan.h"
#include "bis_sink.h"
#include "usb_out.h"
#include "ll_capture.h"
#include "sniffer_tap.h"

#include <ctype.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/shell/shell.h>
#include <zephyr/bluetooth/addr.h>

#define MAX_LIST 8

static atomic_t s_mode = ATOMIC_INIT(SNIFFER_MODE_M2);

enum sniffer_mode sniffer_cli_mode(void)
{
	return (enum sniffer_mode)atomic_get(&s_mode);
}

static const char *mode_str(enum sniffer_mode m)
{
	switch (m) {
	case SNIFFER_MODE_M1: return "m1 (HCI ISO Data; pcap DLT 187 BLUETOOTH_HCI_H4)";
	case SNIFFER_MODE_M2: return "m2 (raw LL PDU; pcap DLT 256 BLUETOOTH_LE_LL_WITH_PHDR)";
	default:              return "?";
	}
}

static int cmd_stop(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (!sniffer_bis_sink_is_active()) {
		shell_warn(sh, "sniff not running");
		return 0;
	}
	sniffer_bis_sink_stop();
	shell_print(sh, "sniff stopped");
	return 0;
}

static int cmd_start(const struct shell *sh, size_t argc, char **argv)
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

	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(&cand.addr, addr, sizeof(addr));
	shell_print(sh, "locking on %s sid=%u name='%s'",
		    addr, cand.sid, cand.name);

	err = sniffer_bis_sink_start(&cand);
	if (err) {
		shell_error(sh, "start failed: %d", err);
		return err;
	}
	shell_print(sh, "sniffing - use `sniff status` to inspect");
	return 0;
}

static int cmd_raw(const struct shell *sh, size_t argc, char **argv)
{
	if (argc == 1) {
		shell_print(sh, "raw = %s",
			    sniffer_tap_raw_enc_get() ? "on" : "off");
		return 0;
	}
	if (argc != 2) {
		shell_error(sh, "usage: sniff raw [on|off]");
		return -EINVAL;
	}

	bool on;

	if (strcmp(argv[1], "on") == 0) {
		on = true;
	} else if (strcmp(argv[1], "off") == 0) {
		on = false;
	} else {
		shell_error(sh, "unknown '%s' (use on|off)", argv[1]);
		return -EINVAL;
	}
	if (sniffer_bis_sink_is_active()) {
		shell_error(sh, "sniff is running - `sniff stop` before changing raw");
		return -EBUSY;
	}

	sniffer_tap_raw_enc_set(on);
	shell_print(sh, "raw = %s  (encrypted BIGs sync without bcode; "
			"ciphertext + MIC forwarded to Wireshark)",
		    on ? "on" : "off");
	return 0;
}

static int cmd_mode(const struct shell *sh, size_t argc, char **argv)
{
	if (argc == 1) {
		shell_print(sh, "mode = %s", mode_str(sniffer_cli_mode()));
		return 0;
	}
	if (argc != 2) {
		shell_error(sh, "usage: sniff mode [m1|m2]");
		return -EINVAL;
	}

	enum sniffer_mode next;
	if (strcmp(argv[1], "m1") == 0) {
		next = SNIFFER_MODE_M1;
	} else if (strcmp(argv[1], "m2") == 0) {
		next = SNIFFER_MODE_M2;
	} else {
		shell_error(sh, "unknown mode '%s' (use m1 or m2)", argv[1]);
		return -EINVAL;
	}

	atomic_set(&s_mode, (atomic_val_t)next);
	shell_print(sh, "mode = %s", mode_str(next));
	shell_print(sh, "-> reopen the Wireshark extcap and pick the matching DLT");
	if (next == SNIFFER_MODE_M1 && sniffer_bis_sink_is_active()) {
		shell_warn(sh, "switched to M1 while already running - restart sniff"
				"to actually get HCI ISO Data records");
	}
	return 0;
}

static int cmd_single_bis(const struct shell *sh, size_t argc, char **argv)
{
	if (argc == 1) {
		shell_print(sh, "single_bis = %s",
			    sniffer_bis_sink_get_single_bis() ? "on" : "off");
		return 0;
	}
	if (argc != 2) {
		shell_error(sh, "usage: sniff single_bis [on|off]");
		return -EINVAL;
	}
	bool on;
	if (strcmp(argv[1], "on") == 0) {
		on = true;
	} else if (strcmp(argv[1], "off") == 0) {
		on = false;
	} else {
		shell_error(sh, "unknown '%s' (use on|off)", argv[1]);
		return -EINVAL;
	}
	sniffer_bis_sink_set_single_bis(on);
	shell_print(sh, "single_bis = %s  (applies at next `sniff start`)",
		    on ? "on" : "off");
	if (on) {
		shell_print(sh, "-> sync only to BIS 1. Enables control-subevent capture "
				"under interleaved packing at the cost of BIS 2 data.");
	}
	return 0;
}

static int cmd_ctrl_probe(const struct shell *sh, size_t argc, char **argv)
{
	if (argc == 1) {
		shell_print(sh, "ctrl_probe = %s",
			    sniffer_tap_ctrl_probe_get() ? "on" : "off");
		return 0;
	}
	if (argc != 2) {
		shell_error(sh, "usage: sniff ctrl_probe [on|off]");
		return -EINVAL;
	}
	bool on;
	if (strcmp(argv[1], "on") == 0) {
		on = true;
	} else if (strcmp(argv[1], "off") == 0) {
		on = false;
	} else {
		shell_error(sh, "unknown '%s' (use on|off)", argv[1]);
		return -EINVAL;
	}
	sniffer_tap_ctrl_probe_set(on);
	shell_print(sh, "ctrl_probe = %s  (force control-subevent RX every BIG event)",
		    on ? "on" : "off");
	return 0;
}

static int cmd_greedy(const struct shell *sh, size_t argc, char **argv)
{
	if (argc == 1) {
		shell_print(sh, "greedy = %s",
			    sniffer_tap_greedy_get() ? "on" : "off");
		return 0;
	}
	if (argc != 2) {
		shell_error(sh, "usage: sniff greedy [on|off]");
		return -EINVAL;
	}
	bool on;
	if (strcmp(argv[1], "on") == 0) {
		on = true;
	} else if (strcmp(argv[1], "off") == 0) {
		on = false;
	} else {
		shell_error(sh, "unknown '%s' (use on|off)", argv[1]);
		return -EINVAL;
	}
	sniffer_tap_greedy_set(on);
	shell_print(sh, "greedy = %s  (bypass LLL 'payload already received' skip)",
		    on ? "on" : "off");
	return 0;
}

static int cmd_payload_omit(const struct shell *sh, size_t argc, char **argv)
{
	if (argc == 1) {
		shell_print(sh, "payload_omit = %s",
			    sniffer_tap_payload_omit_get() ? "on" : "off");
		return 0;
	}
	if (argc != 2) {
		shell_error(sh, "usage: sniff payload_omit [on|off]");
		return -EINVAL;
	}
	bool on;
	if (strcmp(argv[1], "on") == 0) {
		on = true;
	} else if (strcmp(argv[1], "off") == 0) {
		on = false;
	} else {
		shell_error(sh, "unknown '%s' (use on|off)", argv[1]);
		return -EINVAL;
	}
	sniffer_tap_payload_omit_set(on);
	shell_print(sh, "payload_omit = %s  (header-only capture: timing/header kept, "
			"payload bytes replaced with a fake pattern)",
		    on ? "on" : "off");
	return 0;
}

static int cmd_reset_probes(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	sniffer_tap_probe_reset();
	shell_print(sh, "probes reset");
	return 0;
}

static int cmd_status(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	char status[192];
	sniffer_bis_sink_status(status, sizeof(status));
	shell_print(sh, "mode=%s", mode_str(sniffer_cli_mode()));
	shell_print(sh, "scan=%s raw=%s %s",
		    sniffer_scan_is_active() ? "on" : "off",
		    sniffer_tap_raw_enc_get() ? "on" : "off",
		    status);
	shell_print(sh, "usb: dtr=%d bytes=%llu drops=%u",
		    (int)sniffer_usb_out_dtr(),
		    (unsigned long long)sniffer_usb_out_bytes_written(),
		    sniffer_usb_out_dropped_records());
	shell_print(sh, "lll_tap: forwarded=%u framing_drops=%u ring_drops=%u "
			"single_bis=%s ctrl_probe=%s greedy=%s "
			"payload_omit=%s",
		    sniffer_ll_capture_forwarded(),
		    sniffer_ll_capture_dropped(),
		    sniffer_tap_dropped(),
		    sniffer_bis_sink_get_single_bis() ? "on" : "off",
		    sniffer_tap_ctrl_probe_get() ? "on" : "off",
		    sniffer_tap_greedy_get() ? "on" : "off",
		    sniffer_tap_payload_omit_get() ? "on" : "off");
	shell_print(sh, "lll_tap ctrl_se: detected=%u forwarded=%u",
		    sniffer_tap_ctrl_se_detected(),
		    sniffer_tap_ctrl_se_forwarded());

	uint16_t cur = 0, nxt = 0;
	sniffer_tap_last_cssn(&cur, &nxt);
	shell_print(sh, "lll_tap diag: bis_hooks=%u bis_max_seen=%u "
			"ctrl_flag_seen=%u cssn_curr=%u cssn_next=%u",
		    sniffer_tap_bis_hook_calls(),
		    sniffer_tap_bis_max_at_hook(),
		    sniffer_tap_ctrl_flag_at_hook(),
		    cur, nxt);
	shell_print(sh, "lll probes: bis_max_marked=%u ctrl_check=%u/%u "
			"ctrl_set=%u ctrl_recv=%u fwd=%u",
		    sniffer_tap_bis_max_marked(),
		    sniffer_tap_ctrl_check_true(),
		    sniffer_tap_ctrl_check_reached(),
		    sniffer_tap_ctrl_set_marked(),
		    sniffer_tap_ctrl_recv_marked(),
		    sniffer_tap_ctrl_recv_forwarded());
	shell_print(sh, "lll notrx: total=%u with_ctrl=%u arm_miss=%u",
		    sniffer_tap_notrx_total(),
		    sniffer_tap_notrx_ctrl(),
		    sniffer_tap_arm_misses());
	{
		const uint32_t seen = sniffer_tap_events_seen();
		const uint32_t full = sniffer_tap_events_full_data();
		const uint32_t clean = sniffer_tap_events_no_arm_miss();
		const uint32_t captured = sniffer_tap_payloads_captured();
		const uint32_t expected = sniffer_tap_payloads_expected();
		const uint32_t full_pct = seen ? (full * 100U) / seen : 0U;
		const uint32_t clean_pct = seen ? (clean * 100U) / seen : 0U;
		const uint32_t cov_pct = expected ? (captured * 100U) / expected : 0U;
		shell_print(sh,
			    "lll events: seen=%u full_data=%u (%u%%) "
			    "no_arm_miss=%u (%u%%) payload_coverage=%u/%u (%u%%)",
			    seen, full, full_pct, clean, clean_pct,
			    captured, expected, cov_pct);
	}
	shell_print(sh, "lll timings: isr=%u/%u us (max/mean, n=%u) "
			"tap=%u/%u us (max/mean)  a=%u b=%u c=%u us (mean)",
		    sniffer_tap_probe_isr_max_us(),
		    sniffer_tap_probe_isr_mean_us(),
		    sniffer_tap_probe_isr_count(),
		    sniffer_tap_probe_tap_max_us(),
		    sniffer_tap_probe_tap_mean_us(),
		    sniffer_tap_probe_a_mean_us(),
		    sniffer_tap_probe_b_mean_us(),
		    sniffer_tap_probe_c_mean_us());
	{
		char lat_line[128];
		size_t lo = 0;
		uint8_t bins = sniffer_tap_latency_bins();

		for (uint8_t b = 0; b < bins; b++) {
			int w = snprintk(lat_line + lo, sizeof(lat_line) - lo,
					 " %5u", sniffer_tap_latency_bin(b));
			if (w < 0 || (size_t)w >= sizeof(lat_line) - lo) {
				break;
			}
			lo += (size_t)w;
		}
		shell_print(sh,
			    "lll prep latency: events=%u max=%u  histogram [0..%u+]:%s",
			    sniffer_tap_latency_events(),
			    sniffer_tap_latency_max(),
			    bins - 1U, lat_line);
	}
	{
		uint32_t prep = sniffer_tap_events_prepared();
		uint32_t with0 = sniffer_tap_events_with_slot0();
		uint32_t pct = prep ? (with0 * 100U) / prep : 0U;

		shell_print(sh,
			    "lll prep: events_prepared=%u events_with_slot0=%u (%u%%)  "
			    "widening now/max = %u/%u us",
			    prep, with0, pct,
			    sniffer_tap_widening_last_us(),
			    sniffer_tap_widening_max_us());
	}
	shell_print(sh,
		    "lll anchor delta us: last=%u min=%u mean=%u max=%u  n=%u",
		    sniffer_tap_anchor_delta_last(),
		    sniffer_tap_anchor_delta_min(),
		    sniffer_tap_anchor_delta_mean(),
		    sniffer_tap_anchor_delta_max(),
		    sniffer_tap_anchor_delta_count());
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sniff_cmds,
	SHELL_CMD_ARG(start, NULL,
		      "[<target>] - lock onto broadcaster (default: first)",
		      cmd_start, 1, 1),
	SHELL_CMD(stop, NULL, "Tear down BIG sync", cmd_stop),
	SHELL_CMD_ARG(mode, NULL,
		      "[m1|m2] - HCI ISO Data (m1) vs raw LL (m2)",
		      cmd_mode, 1, 1),
	SHELL_CMD_ARG(single_bis, NULL,
		      "[on|off] - sync to BIS 1 only (needed for control-subevent capture)",
		      cmd_single_bis, 1, 1),
	SHELL_CMD_ARG(bcode, NULL,
		      "<target> <hex1..16>|clear - alias for `scan bcode`",
		      sniffer_scan_bcode_cmd, 3, 0),
	SHELL_CMD_ARG(raw, NULL,
		      "[on|off] - sync encrypted BIGs without bcode; forward "
		      "ciphertext + MIC to Wireshark",
		      cmd_raw, 1, 1),
	SHELL_CMD_ARG(ctrl_probe, NULL,
		      "[on|off] - force control-subevent RX every BIG event (debug)",
		      cmd_ctrl_probe, 1, 1),
	SHELL_CMD_ARG(greedy, NULL,
		      "[on|off] - capture every wire subevent (bypass LLL 'already received' skip)",
		      cmd_greedy, 1, 1),
	SHELL_CMD_ARG(payload_omit, NULL,
		      "[on|off] - header-only capture: keep timing/header, replace payload bytes",
		      cmd_payload_omit, 1, 1),
	SHELL_CMD(reset_probes, NULL,
		  "Reset ISR + tap timing probes for a fresh measurement",
		  cmd_reset_probes),
	SHELL_CMD(status, NULL, "Show sniffer + USB status", cmd_status),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sniff, &sniff_cmds, "Auracast BIS sniffer", NULL);

int sniffer_cli_init(void)
{
	return 0;
}
