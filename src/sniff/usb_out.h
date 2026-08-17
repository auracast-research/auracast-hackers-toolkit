/*
 * Binary output over the dedicated CDC-ACM data endpoint.
 *
 * The write path is atomic per record: if the ring can't hold the
 * whole buffer, the entire write is dropped and the drop counter
 * increments. Partial records would corrupt the downstream PCAP
 * stream in the extcap.
 */

#ifndef SNIFFER_USB_OUT_H_
#define SNIFFER_USB_OUT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int sniffer_usb_out_init(void);

int sniffer_usb_out_write(const uint8_t *data, size_t len);

uint32_t sniffer_usb_out_dropped_records(void);

uint64_t sniffer_usb_out_bytes_written(void);

bool sniffer_usb_out_dtr(void);

#endif /* SNIFFER_USB_OUT_H_ */
