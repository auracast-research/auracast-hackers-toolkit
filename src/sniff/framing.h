/*
 * Packet format between the sniffer firmware and the host extcap.
 *
 * Common header (all LE):
 *   u16 MAGIC   0xB1E4 = LL PDU record (BIS or PA)
 *   u16 LEN     payload bytes that follow, excluding MAGIC+LEN
 *   u64 DEV_TS  device uptime in microseconds
 *   ... PAYLOAD (below)
 *
 * Depending on sniffer mode (M1/M2):
 * 
 * M1: PAYLOAD is a raw HCI H4 packet;
 * the extcap emits it as a pcapng EPB, LINKTYPE_BLUETOOTH_HCI_H4 (187).
 *
 * M2: PAYLOAD is
 *   10 B BTLE pseudo-header, 4 B access address (LE),
 *   N B PDU (2 B header + payload), 3 B CRC placeholder,
 *   plus an optional trailer iff LEN leaves room:
 *   u16 META_TRAILER_MAGIC (0xB1E7), u16 META_LEN, then 16 B meta:
 *     u16  event_counter  (sniffer_tap_pdu::event_counter)
 *     u8   bis            (1..num_bis; 0 = PA record)
 *     u8   chan           (0..36, = phdr rf_channel)
 *     u8   subevent       (linear within-BIS)
 *     u8   bn_curr, irc_curr, ptc_curr, cssn_curr, cssn_next
 *     u8   derived        (SNIFFER_TAP_DFLAG_* bitmap)
 *     u8   seq            (per-record, wraps mod 256;
 *                          gap vs previous seq+1 = loss)
 *     u32  payload_number (BIS SDU counter, low 32 of 39 bits)
 * The extcap emits [phdr..CRC] as a pcapng EPB,
 * LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256), meta as opt_comment.
 */

#ifndef SNIFFER_FRAMING_H_
#define SNIFFER_FRAMING_H_

#include <stddef.h>
#include <stdint.h>
#include <zephyr/bluetooth/iso.h>

#include "sniffer_tap.h"

int sniffer_framing_init(void);

int sniffer_framing_emit_iso_sdu(uint16_t handle,
				 const struct bt_iso_recv_info *info,
				 const uint8_t *data, uint16_t len);

int sniffer_framing_emit_ll_pdu(const struct sniffer_tap_pdu *rec);

#endif /* SNIFFER_FRAMING_H_ */
