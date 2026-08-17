#include "scan.h"
#include "big_sync.h"

#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gap.h>
#include <zephyr/net_buf.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>

LOG_MODULE_REGISTER(sniffer_scan, LOG_LEVEL_INF);

#define MAX_CANDIDATES 8

static struct sniffer_candidate cands[MAX_CANDIDATES];
static struct k_mutex cands_mu;
static bool scan_active;

struct parsed_ext_adv {
	char     name[SNIFFER_CAND_NAME_MAX];
	uint32_t broadcast_id;
	bool     has_broadcast_id;
};

/* Auracast Broadcast Audio Announcement Service Data: 2-byte UUID
 * (0x1852) followed by a 3-byte broadcast_id. Anything else is
 * ignored.
 */
#define BT_UUID_BROADCAST_AUDIO_VAL 0x1852U

static bool ext_adv_parser(struct bt_data *data, void *user_data)
{
	struct parsed_ext_adv *p = user_data;
	size_t len;

	switch (data->type) {
	case BT_DATA_NAME_SHORTENED:
	case BT_DATA_NAME_COMPLETE:
	case BT_DATA_BROADCAST_NAME:  /* we need to check all these types for the name */
		if (p->name[0] != '\0') {
			/* Keep the first name we see, broadcast name
			 * prioritized over local name if both appear */
			break;
		}
		len = MIN(data->data_len, SNIFFER_CAND_NAME_MAX - 1);
		memcpy(p->name, data->data, len);
		p->name[len] = '\0';
		break;
	case BT_DATA_SVC_DATA16:
		if (data->data_len < 5U) {
			break;
		}
		{
			uint16_t uuid = sys_get_le16(data->data);

			if (uuid != BT_UUID_BROADCAST_AUDIO_VAL) {
				break;
			}
			p->broadcast_id = sys_get_le24(data->data + 2);
			p->has_broadcast_id = true;
		}
		break;
	default:
		break;
	}
	return true;
}

static struct sniffer_candidate *find_slot(const bt_addr_le_t *addr, uint8_t sid,
					   bool *is_existing_match)
{
	*is_existing_match = false;

	for (int i = 0; i < MAX_CANDIDATES; i++) {
		if (cands[i].valid && cands[i].sid == sid &&
		    bt_addr_le_cmp(&cands[i].addr, addr) == 0) {
			*is_existing_match = true;
			return &cands[i];
		}
	}
	for (int i = 0; i < MAX_CANDIDATES; i++) {
		if (!cands[i].valid) {
			return &cands[i];
		}
	}
	int idx = 0;
	int8_t weakest = INT8_MAX;
	for (int i = 0; i < MAX_CANDIDATES; i++) {
		if (cands[i].rssi < weakest) {
			weakest = cands[i].rssi;
			idx = i;
		}
	}
	return &cands[idx];
}

static void scan_recv(const struct bt_le_scan_recv_info *info,
		      struct net_buf_simple *buf)
{
	/* We only care about ext-adv PDUs that advertise a periodic
	 * interval. */
	if (info->interval == 0U) {
		return;
	}

	struct parsed_ext_adv p = {0};

	bt_data_parse(buf, ext_adv_parser, &p);

	k_mutex_lock(&cands_mu, K_FOREVER);
	bool is_existing;
	struct sniffer_candidate *slot = find_slot(info->addr, info->sid, &is_existing);

	uint8_t saved_bcode[SNIFFER_CAND_BCODE_MAX];
	uint8_t saved_bcode_len = 0U;

	if (is_existing) {
		memcpy(saved_bcode, slot->bcode, sizeof(saved_bcode));
		saved_bcode_len = slot->bcode_len;
	}

	memset(slot, 0, sizeof(*slot));
	slot->valid          = true;
	slot->sid            = info->sid;
	slot->rssi           = info->rssi;
	slot->pa_interval_us = BT_CONN_INTERVAL_TO_US(info->interval);
	bt_addr_le_copy(&slot->addr, info->addr);
	if (p.name[0] != '\0') {
		memcpy(slot->name, p.name, sizeof(slot->name));
	}
	if (p.has_broadcast_id) {
		slot->broadcast_id     = p.broadcast_id;
		slot->has_broadcast_id = true;
	}
	if (saved_bcode_len > 0U) {
		memcpy(slot->bcode, saved_bcode, sizeof(saved_bcode));
		slot->bcode_len = saved_bcode_len;
	}
	k_mutex_unlock(&cands_mu);
}

static struct bt_le_scan_cb scan_cb = {
	.recv = scan_recv,
};

int sniffer_scan_init(void)
{
	k_mutex_init(&cands_mu);
	bt_le_scan_cb_register(&scan_cb);
	return 0;
}

int sniffer_scan_start(void)
{
	if (scan_active) {
		return 0;
	}

	struct bt_le_scan_param params = {
		.type       = BT_LE_SCAN_TYPE_ACTIVE,
		.options    = BT_LE_SCAN_OPT_NONE,
		.interval   = BT_GAP_SCAN_FAST_INTERVAL,
		.window     = BT_GAP_SCAN_FAST_WINDOW,
	};

	int err = bt_le_scan_start(&params, NULL);
	if (err == 0) {
		scan_active = true;
	}
	return err;
}

int sniffer_scan_stop(void)
{
	if (!scan_active) {
		return 0;
	}
	int err = bt_le_scan_stop();
	if (err == 0) {
		scan_active = false;
	}
	return err;
}

bool sniffer_scan_is_active(void)
{
	return scan_active;
}

size_t sniffer_scan_get_candidates(struct sniffer_candidate *out, size_t max)
{
	size_t n = 0;

	k_mutex_lock(&cands_mu, K_FOREVER);
	for (int i = 0; i < MAX_CANDIDATES && n < max; i++) {
		if (cands[i].valid) {
			out[n++] = cands[i];
		}
	}
	k_mutex_unlock(&cands_mu);
	return n;
}

void sniffer_scan_clear_candidates(void)
{
	k_mutex_lock(&cands_mu, K_FOREVER);
	memset(cands, 0, sizeof(cands));
	k_mutex_unlock(&cands_mu);
}

static bool addr_match_by_bytes(const bt_addr_le_t *a, const bt_addr_le_t *b)
{
	return memcmp(a->a.val, b->a.val, sizeof(a->a.val)) == 0;
}

static struct sniffer_candidate *nth_valid_locked(size_t n)
{
	size_t count = 0U;

	for (int i = 0; i < MAX_CANDIDATES; i++) {
		if (cands[i].valid) {
			if (count == n) {
				return &cands[i];
			}
			count++;
		}
	}
	return NULL;
}

static struct sniffer_candidate *lookup_locked(const char *tok)
{
	if (tok == NULL) {
		return nth_valid_locked(0);
	}

	if (tok[0] != '\0') {
		char *endptr = NULL;
		long idx = strtol(tok, &endptr, 10);

		if (endptr != tok && *endptr == '\0' && idx >= 0) {
			return nth_valid_locked((size_t)idx);
		}
	}

	/* Address match (either type). */
	bt_addr_le_t want;

	if (bt_addr_le_from_str(tok, "random", &want) == 0 ||
	    bt_addr_le_from_str(tok, "public", &want) == 0) {
		for (int i = 0; i < MAX_CANDIDATES; i++) {
			if (cands[i].valid &&
			    addr_match_by_bytes(&cands[i].addr, &want)) {
				return &cands[i];
			}
		}
	}

	/* Name substring. */
	for (int i = 0; i < MAX_CANDIDATES; i++) {
		if (cands[i].valid && strstr(cands[i].name, tok) != NULL) {
			return &cands[i];
		}
	}

	return NULL;
}

int sniffer_scan_lookup(const char *tok, struct sniffer_candidate *out)
{
	int rc = -ENOENT;

	k_mutex_lock(&cands_mu, K_FOREVER);

	struct sniffer_candidate *slot = lookup_locked(tok);

	if (slot != NULL) {
		*out = *slot;
		rc = 0;
	}

	k_mutex_unlock(&cands_mu);
	return rc;
}

int sniffer_scan_set_bcode(const char *tok, const uint8_t *bcode,
			   size_t bcode_len)
{
	if (bcode_len > SNIFFER_CAND_BCODE_MAX) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&cands_mu, K_FOREVER);

	struct sniffer_candidate *slot = lookup_locked(tok);
	int rc;

	if (slot == NULL) {
		rc = -ENOENT;
	} else {
		memset(slot->bcode, 0, sizeof(slot->bcode));
		if (bcode_len > 0U) {
			memcpy(slot->bcode, bcode, bcode_len);
		}
		slot->bcode_len = (uint8_t)bcode_len;
		rc = 0;
	}

	k_mutex_unlock(&cands_mu);
	return rc;
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
	return -1;
}

int sniffer_scan_parse_hex(const char *s, uint8_t *out, size_t out_max,
			   size_t *out_len)
{
	size_t n = 0;

	while (*s && n < out_max) {
		if (*s == ':' || *s == '-' || *s == ' ') {
			s++;
			continue;
		}
		int hi = hex_nibble(*s++);

		if (hi < 0) return -EINVAL;
		int lo = hex_nibble(*s++);

		if (lo < 0) return -EINVAL;
		out[n++] = (uint8_t)((hi << 4) | lo);
	}
	if (*s != '\0') return -EMSGSIZE;
	*out_len = n;
	return 0;
}

static int cmd_scan_on(const struct shell *sh, size_t argc, char **argv)
{
	int err;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (sniffer_scan_is_active()) {
		shell_warn(sh, "scan already running");
		return 0;
	}
	err = sniffer_scan_start();
	if (err) {
		shell_error(sh, "scan start failed: %d", err);
		return err;
	}
	shell_print(sh, "scan started");
	return 0;
}

static int cmd_scan_off(const struct shell *sh, size_t argc, char **argv)
{
	int err;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!sniffer_scan_is_active()) {
		shell_warn(sh, "scan not running");
		return 0;
	}
	err = sniffer_scan_stop();
	if (err) {
		shell_error(sh, "scan stop failed: %d", err);
		return err;
	}
	shell_print(sh, "scan stopped");
	return 0;
}

static int cmd_scan_list(const struct shell *sh, size_t argc, char **argv)
{
	struct sniffer_candidate found[MAX_CANDIDATES];
	size_t n;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	n = sniffer_scan_get_candidates(found, ARRAY_SIZE(found));
	if (n == 0U) {
		shell_print(sh, "no broadcast candidates yet,  `scan on` and wait a few seconds");
		return 0;
	}
	for (size_t i = 0U; i < n; i++) {
		char addr_str[BT_ADDR_LE_STR_LEN];
		char bid_str[8];

		bt_addr_le_to_str(&found[i].addr, addr_str, sizeof(addr_str));
		if (found[i].has_broadcast_id) {
			snprintk(bid_str, sizeof(bid_str), "%06x",
				 (unsigned)found[i].broadcast_id);
		} else {
			bid_str[0] = '-';
			bid_str[1] = '\0';
		}
		shell_print(sh, "%zu: %s sid=%u rssi=%d bid=%s bcode=%s name='%s'",
			    i, addr_str, found[i].sid,
			    (int)found[i].rssi, bid_str,
			    found[i].bcode_len ? "set" : "-",
			    found[i].name);
	}
	return 0;
}

static int cmd_scan_clear(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	sniffer_scan_clear_candidates();
	shell_print(sh, "candidate list cleared");
	return 0;
}


static int cmd_scan_biginfo(const struct shell *sh, size_t argc, char **argv)
{
	struct sniffer_candidate cand;
	struct bt_iso_biginfo bi = {0};
	const char *tok = (argc >= 2) ? argv[1] : NULL;
	int err;

	err = sniffer_scan_lookup(tok, &cand);
	if (err) {
		if (tok == NULL) {
			shell_error(sh, "no broadcast candidates yes, `scan on` first");
		} else {
			shell_error(sh, "no matching candidate for '%s',  "
					"`scan list` to see options", tok);
		}
		return err;
	}

	char addr_str[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(&cand.addr, addr_str, sizeof(addr_str));
	shell_print(sh, "scan biginfo: fetching from %s sid=%u name='%s'",
		    addr_str, cand.sid, cand.name);

	err = big_sync_biginfo_only(&cand, &bi, NULL, NULL, sh);
	if (err) {
		shell_error(sh, "biginfo failed: %d", err);
		return err;
	}

	/* iso_interval in units of 1.25 ms per Core spec */
	uint32_t iso_us = (uint32_t)bi.iso_interval * 1250U;

	shell_print(sh,
		    "  num_bis=%u nse=%u iso_int=%u.%03u ms bn=%u irc=%u pto=%u",
		    bi.num_bis, bi.sub_evt_count,
		    iso_us / 1000U, iso_us % 1000U,
		    bi.burst_number, bi.rep_count, bi.offset);
	shell_print(sh,
		    "  max_pdu=%u max_sdu=%u sdu_int=%u framing=%u phy=%u enc=%u",
		    bi.max_pdu, bi.max_sdu, bi.sdu_interval,
		    bi.framing, bi.phy, bi.encryption);
	return 0;
}

int sniffer_scan_bcode_cmd(const struct shell *sh, size_t argc, char **argv)
{
	if (argc != 3) {
		shell_error(sh, "usage: bcode <target> <hex1..16>|clear");
		return -EINVAL;
	}

	const char *tok = argv[1];
	const char *val = argv[2];

	if (strcmp(val, "clear") == 0) {
		int err = sniffer_scan_set_bcode(tok, NULL, 0);

		if (err) {
			shell_error(sh, "no matching candidate for '%s'", tok);
			return err;
		}
		shell_print(sh, "bcode cleared on '%s'", tok);
		return 0;
	}

	uint8_t tmp[SNIFFER_CAND_BCODE_MAX] = {0};
	size_t n = 0;
	int err = sniffer_scan_parse_hex(val, tmp, sizeof(tmp), &n);

	if (err) {
		shell_error(sh, "invalid hex (need 1..16 bytes)");
		return err;
	}
	err = sniffer_scan_set_bcode(tok, tmp, n);
	if (err) {
		shell_error(sh, "no matching candidate for '%s'", tok);
		return err;
	}
	shell_print(sh, "bcode set on '%s' (%u bytes, zero-padded to 16)",
		    tok, (unsigned)n);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_scan,
	SHELL_CMD(on,    NULL, "Start scanning",             cmd_scan_on),
	SHELL_CMD(off,   NULL, "Stop scanning",              cmd_scan_off),
	SHELL_CMD(list,  NULL, "List discovered candidates", cmd_scan_list),
	SHELL_CMD(clear, NULL, "Clear the candidate list",   cmd_scan_clear),
	SHELL_CMD_ARG(biginfo, NULL,
		      "[<target>] (PA sync, dump BIGInfo)",
		      cmd_scan_biginfo, 1, 1),
	SHELL_CMD_ARG(bcode, NULL,
		      "<target> <hex1..16>|clear (per-candidate broadcast_code)",
		      sniffer_scan_bcode_cmd, 3, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(scan, &sub_scan,
		   "scan: Auracast BIG discovery",
		   NULL);
