#ifndef ZEPHYR_INCLUDE_BT_CTLR_SNIFFER_TAP_PDU_H_
#define ZEPHYR_INCLUDE_BT_CTLR_SNIFFER_TAP_PDU_H_

#include <stdint.h>

#define SNIFFER_TAP_PDU_MAX 256

#define SNIFFER_TAP_FLAG_CRC_OK   (1U << 0)
#define SNIFFER_TAP_FLAG_RSSI_VAL (1U << 1)
#define SNIFFER_TAP_FLAG_ENC      (1U << 2)
#define SNIFFER_TAP_FLAG_MIC_OK   (1U << 3)
/* Header-only capture mode, pdu_len still reports the true PDU length, but pdu[] holds only the
 * 2-byte header (LLID + length). The consumer fills the packet with a fake byte pattern.
 */
#define SNIFFER_TAP_FLAG_PAYLOAD_OMITTED (1U << 4)

/* Derived flags for the BIS-record extended metadata (BIS kind only). */
#define SNIFFER_TAP_DFLAG_RETRANSMISSION   (1U << 0)  /* irc_curr > 1  */
#define SNIFFER_TAP_DFLAG_PRETRANSMISSION  (1U << 1)  /* ptc_curr > 0  */
#define SNIFFER_TAP_DFLAG_CONTROL          (1U << 2)  /* lll->ctrl (BIG Control Subevent)                       */
#define SNIFFER_TAP_DFLAG_INTERLEAVED      (1U << 3)  /* BIG uses interleaved packing (lll->interleaved)         */
#define SNIFFER_TAP_DFLAG_FIRST_EVENT_RX   (1U << 4)  /* first successful RX in this BIG event (anchor RX)       */
#define SNIFFER_TAP_DFLAG_CIPHERTEXT       (1U << 5)  /* PDU was encrypted, PDU bytes emitted as ciphertext + MIC */

#define SNIFFER_TAP_KIND_BIS       0U  /* BIS Data / Control PDU on data channel      */
#define SNIFFER_TAP_KIND_PA        1U  /* Periodic-adv PDU (AUX_SYNC_IND / chain)     */

struct sniffer_tap_pdu {
	uint64_t timestamp_us;    /* device uptime in microseconds */
	uint32_t access_addr;     /* AA on the wire, little-endian layout       */
	uint16_t event_counter;   /* BIG event counter (BIS kind only)          */
	uint8_t  subevent;        /* linear within-BIS SE index (BIS only)      */
	uint8_t  bis;             /* 1..num_bis (BIS only, 0 otherwise)         */
	uint8_t  chan;            /* 0..36 data channel index                    */
	uint8_t  phy;             /* PHY_1M=1, PHY_2M=2, PHY_CODED=4             */
	int8_t   rssi_dbm;        /* absolute dBm, negative                      */
	uint8_t  flags;           /* SNIFFER_TAP_FLAG_*                          */
	uint8_t  pdu_kind;        /* SNIFFER_TAP_KIND_*                          */
	uint16_t pdu_len;         /* wire bytes in pdu[]: 2 hdr + payload        */

	/* Extended per-PDU BIG state (BIS kind only; zero for PA).  */
	uint8_t  bn_curr;         /* 1..bn                                       */
	uint8_t  irc_curr;        /* 1..irc                                      */
	uint8_t  ptc_curr;        /* 0..ptc                                      */
	uint8_t  cssn_curr;       /* 0..7 snapshot at RX                         */
	uint8_t  cssn_next;       /* 0..7 latest observed from CSTF-flagged PDU  */
	uint8_t  derived;         /* SNIFFER_TAP_DFLAG_* bitmap                  */

	uint16_t seq_ctr;
	uint64_t payload_number;  /* 39-bit BIS payload counter (SDU identifier) */

	const uint8_t *_deferred_raw;   /* NULL = pdu[] already filled in ISR */
	uint16_t       _deferred_len;   /* bytes to memcpy from _deferred_raw */

	uint8_t  pdu[SNIFFER_TAP_PDU_MAX];
};

typedef void (*sniffer_tap_cb_t)(const struct sniffer_tap_pdu *rec);

#endif /* ZEPHYR_INCLUDE_BT_CTLR_SNIFFER_TAP_PDU_H_ */
