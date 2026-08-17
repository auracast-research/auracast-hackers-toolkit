#ifndef BIG_SYNC_H_
#define BIG_SYNC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/bluetooth/iso.h>
#include <zephyr/shell/shell.h>

#include "scan.h"

int  big_sync_init(void);

int  big_sync_start(const struct sniffer_candidate *cand,
		    const uint8_t *bcode, size_t bcode_len,
		    const struct shell *sh);

int  big_sync_stop(void);
bool big_sync_is_active(void);

void big_sync_status(char *out, size_t out_sz);

#define BIG_SYNC_PA_PAYLOAD_MAX 253U

int  big_sync_biginfo_only(const struct sniffer_candidate *cand,
			   struct bt_iso_biginfo *out_biginfo,
			   uint8_t *out_pa_payload,
			   size_t *out_pa_payload_len,
			   const struct shell *sh);

#endif /* BIG_SYNC_H_ */
