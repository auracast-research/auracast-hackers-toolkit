/*
 * WIP
 */

#ifndef AHT_CLONE_H_
#define AHT_CLONE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/shell/shell.h>

#include "scan.h"

int  clone_init(void);

int  clone_start(const struct sniffer_candidate *cand,
		 const struct shell *sh);

int  clone_stop(void);
bool clone_is_active(void);

void clone_status(char *out, size_t out_sz);

#endif /* AHT_CLONE_H_ */
