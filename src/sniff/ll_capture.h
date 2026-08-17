#ifndef SNIFFER_LL_CAPTURE_H_
#define SNIFFER_LL_CAPTURE_H_

#include <stdint.h>

int sniffer_ll_capture_init(void);

uint32_t sniffer_ll_capture_forwarded(void);
uint32_t sniffer_ll_capture_dropped(void);

#endif /* SNIFFER_LL_CAPTURE_H_ */
