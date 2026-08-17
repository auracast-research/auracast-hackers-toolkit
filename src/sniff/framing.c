#include "framing.h"
#include "usb_out.h"

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>

#define SNIFFER_WIRE_MAGIC          0xB1E4U /* LL PDU record (BIS or PA) */
#define SNIFFER_META_TRAILER_MAGIC  0xB1E7U /* Optional trailer inside LL PDU record */
#define SNIFFER_META_TRAILER_LEN    16U

#define HCI_H4_TYPE_ISO_DATA 0x05U

#define ISO_HDR_PB_COMPLETE_SDU (2U << 12)
#define ISO_HDR_TS_FLAG         BIT(14)

#define FRAME_SCRATCH_BYTES 512U

int sniffer_framing_init(void)
{
	return 0;
}

int sniffer_framing_emit_iso_sdu(uint16_t handle,
				 const struct bt_iso_recv_info *info,
				 const uint8_t *data, uint16_t len)
{
	uint8_t frame[FRAME_SCRATCH_BYTES];
	uint8_t *p = frame;

	const uint16_t iso_load_len   = 4U + 2U + 2U + len; /* TS + seq + sdu_len + sdu */
	const uint16_t hci_body_total = 1U + 4U + iso_load_len; /* H4 type + HCI hdr + load */
	const uint16_t framed_payload = 8U + hci_body_total;    /* dev ts + HCI body */
	const size_t total_wire       = 4U + framed_payload;    /* magic + len + payload */

	if (total_wire > sizeof(frame)) {
		return -EMSGSIZE;
	}

	uint64_t dev_ts_us = k_ticks_to_us_floor64(k_uptime_ticks());

	/* Wire preamble. */
	sys_put_le16(SNIFFER_WIRE_MAGIC, p); p += 2;
	sys_put_le16(framed_payload,     p); p += 2;
	sys_put_le64(dev_ts_us,          p); p += 8;

	/* HCI H4 type byte. */
	*p++ = HCI_H4_TYPE_ISO_DATA;

	/* HCI ISO Data header:
	 *   [15]     RFU
	 *   [14]     TS_Flag
	 *   [13:12]  PB_Flag
	 *   [11:0]   Connection_Handle
	 * then
	 *   [15:14]  RFU
	 *   [13:0]   Data_Total_Length
	 */
	uint16_t hdr0 = (handle & 0x0fffU) | ISO_HDR_PB_COMPLETE_SDU | ISO_HDR_TS_FLAG;
	uint16_t hdr1 = iso_load_len & 0x3fffU;
	sys_put_le16(hdr0, p); p += 2;
	sys_put_le16(hdr1, p); p += 2;

	uint32_t iso_ts = (info && (info->flags & BT_ISO_FLAGS_TS)) ? info->ts : 0U;
	uint16_t seq    = info ? info->seq_num : 0U;

	sys_put_le32(iso_ts, p); p += 4;
	sys_put_le16(seq,    p); p += 2;

	uint16_t sdu_len_field = len & 0x0fffU;
	if (info != NULL) {
		if (info->flags & BT_ISO_FLAGS_LOST) {
			sdu_len_field |= (2U << 14); /* Packet_Status_Flag = 0b10 (lost) */
		} else if (info->flags & BT_ISO_FLAGS_ERROR) {
			sdu_len_field |= (1U << 14); /* Packet_Status_Flag = 0b01 (invalid) */
		}
	}
	sys_put_le16(sdu_len_field, p); p += 2;

	if (data != NULL && len > 0U) {
		memcpy(p, data, len);
		p += len;
	}

	return sniffer_usb_out_write(frame, (size_t)(p - frame));
}

/*
 * BTLE pseudo-header (pcap DLT 256, LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR).
 * 10 bytes, all little-endian. Layout per libpcap docs:
 *   u8  rf_channel                (0..39; BLE channel index if flag bit 6 = 0)
 *   s8  signal_power_dbm          (-128 = unknown)
 *   s8  noise_power_dbm           (-128 = unknown)
 *   u8  access_address_offenses   (bit-error count during AA search)
 *   u32 ref_access_address_le
 *   u16 flags_le
 */
/* Bit positions per libpcap linktypes.h - bits 7..9 are reserved. */
#define BTLE_PHDR_FLAG_DEWHITENED   BIT(0)
#define BTLE_PHDR_FLAG_SIG_VALID    BIT(1)
#define BTLE_PHDR_FLAG_DECRYPTED    BIT(3)
#define BTLE_PHDR_FLAG_REF_AA_VALID BIT(4)
#define BTLE_PHDR_FLAG_CRC_CHECKED  BIT(10)
#define BTLE_PHDR_FLAG_CRC_VALID    BIT(11)
#define BTLE_PHDR_FLAG_MIC_CHECKED  BIT(12)
#define BTLE_PHDR_FLAG_MIC_VALID    BIT(13)

/*
 * Wireshark's BTLE dissector picks "extended advertising PDU" vs
 * "Connection Data PDU" on data channels (<37) by looking at the AA:
 * only 0x8E89BED6 (standard advertising AA) triggers the extended-adv
 * heuristic. Real AUX_SYNC_IND/AUX_CHAIN_IND use the SyncInfo-supplied AA, 
 * but we don't want Wireshark reading them as LL Control PDUs. 
 * So we lie: rewrite the PA record's AA to 0x8E89BED6 in both phdr and 
 * LL PDU. BIGInfo -> BIS AA correlation still works because Wireshark
 * derives BIS AAs from BIGInfo's own seed_access_address field, not
 * from the enclosing PA AA.
 */
#define BTLE_ADV_AA 0x8E89BED6U

int sniffer_framing_emit_ll_pdu(const struct sniffer_tap_pdu *rec)
{
	if (rec == NULL) {
		return -EINVAL;
	}

	uint8_t frame[FRAME_SCRATCH_BYTES];
	uint8_t *p = frame;

	const uint16_t pdu_len        = rec->pdu_len;
	const bool     bis_kind       = (rec->pdu_kind == SNIFFER_TAP_KIND_BIS);
	const uint16_t phdr_len       = 10U;
	const uint16_t aa_len         = 4U;
	const uint16_t crc_len        = 3U;
	const uint16_t ll_pdu_len     = aa_len + pdu_len + crc_len;
	/* Only BIS records carry the metadata trailer, PA records dont */
	const uint16_t meta_trailer_len = bis_kind
					  ? (4U + SNIFFER_META_TRAILER_LEN)
					  : 0U;
	const uint16_t framed_payload = 8U + phdr_len + ll_pdu_len +
					meta_trailer_len;
	const size_t   total_wire     = 4U + framed_payload;

	if (total_wire > sizeof(frame)) {
		return -EMSGSIZE;
	}

	uint32_t wire_aa = rec->access_addr;
	if (rec->pdu_kind == SNIFFER_TAP_KIND_PA) {
		wire_aa = BTLE_ADV_AA;
	}

	sys_put_le16(SNIFFER_WIRE_MAGIC, p); p += 2;
	sys_put_le16(framed_payload,     p); p += 2;
	sys_put_le64(rec->timestamp_us,  p); p += 8;

	/* Pseudo-header. */
	*p++ = rec->chan;
	*p++ = (rec->flags & SNIFFER_TAP_FLAG_RSSI_VAL) ? (uint8_t)rec->rssi_dbm : (uint8_t)0x80;
	*p++ = 0x80;
	*p++ = 0U;
	sys_put_le32(wire_aa, p); p += 4;

	uint16_t phdr_flags = BTLE_PHDR_FLAG_DEWHITENED
			      | BTLE_PHDR_FLAG_REF_AA_VALID
			      | BTLE_PHDR_FLAG_CRC_CHECKED;
	if (rec->flags & SNIFFER_TAP_FLAG_RSSI_VAL) {
		phdr_flags |= BTLE_PHDR_FLAG_SIG_VALID;
	}
	if (rec->flags & SNIFFER_TAP_FLAG_ENC) {
		if (rec->pdu_kind == SNIFFER_TAP_KIND_BIS &&
		    (rec->derived & SNIFFER_TAP_DFLAG_CIPHERTEXT)) {
			phdr_flags |= BTLE_PHDR_FLAG_MIC_CHECKED;
		} else {
			phdr_flags |= BTLE_PHDR_FLAG_DECRYPTED |
				      BTLE_PHDR_FLAG_MIC_CHECKED;
			if (rec->flags & SNIFFER_TAP_FLAG_MIC_OK) {
				phdr_flags |= BTLE_PHDR_FLAG_MIC_VALID;
			}
		}
	}
	if (rec->flags & SNIFFER_TAP_FLAG_CRC_OK) {
		phdr_flags |= BTLE_PHDR_FLAG_CRC_VALID;
	}
	sys_put_le16(phdr_flags, p); p += 2;

	/* LL PDU: [4B AA][PDU: 2 hdr + payload][3B CRC placeholder] */
	sys_put_le32(wire_aa, p); p += 4;
	if (pdu_len > 0U) {
		memcpy(p, rec->pdu, pdu_len);
		if ((rec->flags & SNIFFER_TAP_FLAG_PAYLOAD_OMITTED) &&
		    pdu_len > 2U) {
			/* Header-only capture mode (`sniff payload_omit on`) 
			 * fill payload with 0xFA for the correct length */
			memset(p + 2, 0xFA, pdu_len - 2U);
		}
		p += pdu_len;
	}
	*p++ = 0U; *p++ = 0U; *p++ = 0U;

	if (bis_kind) {
		/* Metadata trailer: extcap parses it out and turns it into a
		 * pcapng opt_comment.
		 */
		sys_put_le16(SNIFFER_META_TRAILER_MAGIC, p); p += 2;
		sys_put_le16(SNIFFER_META_TRAILER_LEN,   p); p += 2;

		sys_put_le16(rec->event_counter, p); p += 2;
		*p++ = rec->bis;
		*p++ = rec->chan;
		*p++ = rec->subevent;
		*p++ = rec->bn_curr;
		*p++ = rec->irc_curr;
		*p++ = rec->ptc_curr;
		*p++ = rec->cssn_curr;
		*p++ = rec->cssn_next;
		*p++ = rec->derived;
		*p++ = (uint8_t)rec->seq_ctr;
		sys_put_le32((uint32_t)rec->payload_number, p); p += 4;
	}

	return sniffer_usb_out_write(frame, (size_t)(p - frame));
}
