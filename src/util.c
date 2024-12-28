#include "auracast_hackers_toolkit.h"

bool is_substring(const char *substr, const char *str) {
	const size_t str_len = strlen(str);
	const size_t sub_str_len = strlen(substr);

	if (sub_str_len > str_len) {
		return false;
	}

	for (size_t pos = 0; pos < str_len; pos++) {
		if (pos + sub_str_len > str_len) {
			return false;
		}

		if (strncasecmp(substr, &str[pos], sub_str_len) == 0) {
			return true;
		}
	}
	return false;
}

const char *phy2str(uint8_t phy) {
	switch (phy) {
	case 0: return "No packets";
	case BT_GAP_LE_PHY_1M: return "LE 1M";
	case BT_GAP_LE_PHY_2M: return "LE 2M";
	case BT_GAP_LE_PHY_CODED: return "LE Coded";
	default: return "Unknown";
	}
}

/* This is copied from controller code. For split builds the linker will fail otherwise. */
uint32_t _util_get_bits(uint8_t *data, uint8_t bit_offs, uint8_t num_bits) {
	uint32_t value;
	uint8_t  shift, byteIdx, bits;

	value = 0;
	shift = 0;
	byteIdx = 0;

	while (num_bits) {
		bits = MIN(num_bits, 8 - bit_offs);
		value |= ((data[byteIdx] >> bit_offs) & BIT_MASK(bits)) << shift;
		shift += bits;
		num_bits -= bits;
		bit_offs = 0;
		byteIdx++;
	}

	return value;
}