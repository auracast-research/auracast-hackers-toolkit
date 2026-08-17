/*
 * Extended/periodic-advertising scan + BIS candidate discovery.
 *
 * The scan module observes ext-adv PDUs that announce a periodic
 * advertising interval.
 */

#ifndef SCAN_H_
#define SCAN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/bluetooth/bluetooth.h>

#define SNIFFER_CAND_NAME_MAX  32
#define SNIFFER_CAND_BCODE_MAX 16

struct sniffer_candidate {
	bool         valid;
	bt_addr_le_t addr;
	uint8_t      sid;
	int8_t       rssi;
	uint32_t     pa_interval_us;
	char         name[SNIFFER_CAND_NAME_MAX];
	uint8_t      bcode[SNIFFER_CAND_BCODE_MAX];
	uint8_t      bcode_len;
	uint32_t     broadcast_id;
	bool         has_broadcast_id;
};

int  sniffer_scan_init(void);
int  sniffer_scan_start(void);
int  sniffer_scan_stop(void);
bool sniffer_scan_is_active(void);

size_t sniffer_scan_get_candidates(struct sniffer_candidate *out, size_t max);
void   sniffer_scan_clear_candidates(void);

/*
 * Look up a candidate:
 *   NULL   -> first valid candidate in the list
 *   "N"    -> N-th valid candidate (`scan list` index)
 *   "AA:BB:CC:DD:EE:FF"    -> match by address
 *   any other string       -> substring match against the name
 *
 * Returns 0 on hit, -ENOENT on miss.
 */
int sniffer_scan_lookup(const char *tok, struct sniffer_candidate *out);

/*
 * Set / clear the bcode on the candidate identified by `tok` (same
 * lookup rules as sniffer_scan_lookup). bcode_len==0 clears. Returns
 * 0 on success, -ENOENT if no matching candidate, -EMSGSIZE if the
 * bcode is longer than SNIFFER_CAND_BCODE_MAX.
 */
int sniffer_scan_set_bcode(const char *tok, const uint8_t *bcode,
			   size_t bcode_len);

/*
 * Parse a hex string like "aa:bb:cc" or "aabbcc" into `out`. Colons,
 * dashes, and spaces are treated as separators. On success, *out_len
 * has the number of decoded bytes. Returns -EINVAL on bad hex,
 * -EMSGSIZE if the decoded byte count would exceed out_max.
 *
 */
int sniffer_scan_parse_hex(const char *s, uint8_t *out, size_t out_max,
			   size_t *out_len);

struct shell;
int sniffer_scan_bcode_cmd(const struct shell *sh, size_t argc, char **argv);

#endif /* SCAN_H_ */
