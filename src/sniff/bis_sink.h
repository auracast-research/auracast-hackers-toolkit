#ifndef SNIFFER_BIS_SINK_H_
#define SNIFFER_BIS_SINK_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "scan.h"

void sniffer_bis_sink_set_single_bis(bool on);
bool sniffer_bis_sink_get_single_bis(void);

int  sniffer_bis_sink_init(void);

/*
 * Establishes PA + BIG sync on the given candidate and sets up the
 * sniffer's output path (M1 host-stack SDU forwarding and/or
 * M2 raw LL PDU streaming).
 *
 * bcode is taken from the candidate itself (set via `scan bcode` /
 * `sniff bcode`). raw-enc mode is taken from the global sniffer_tap
 * raw-enc flag (set via `sniff raw on`). Decision matrix for an
 * encrypted BIG:
 *   - candidate has bcode          -> sync with bcode (CCM decrypts)
 *   - no bcode, raw-enc flag set   -> sync in raw ciphertext mode
 *   - no bcode, raw-enc flag unset -> refuse with -EACCES
 * Unencrypted BIG: sync directly, no bcode / raw handling.
 */
int  sniffer_bis_sink_start(const struct sniffer_candidate *cand);

int  sniffer_bis_sink_stop(void);
bool sniffer_bis_sink_is_active(void);

void sniffer_bis_sink_status(char *out, size_t out_sz);

#endif /* SNIFFER_BIS_SINK_H_ */
