#include "auracast_hackers_toolkit.h"

K_SEM_DEFINE(sem_biginfo, 0U, 1U);

struct broadcast broadcasts[BROADCAST_LIST_MAX_LEN];
uint8_t cur_bcast = 0;

static uint32_t tmp_sub_interval = 0;
static uint32_t tmp_bis_spacing = 0;

void scan_raw_get_biginfo_cb(struct net_buf *buf) {

	struct bt_hci_evt_iso_raw_dump *evt = (void *)buf->data;
	if (evt->type == BT_HCI_EVT_ISO_RAW_DUMP_BIG) {
        uint8_t *binfo = (buf->data + sizeof(*evt));

		/* We can't easily corelate raw PDU with sender addr so we store the values in a global
		 * variable and release the semaphore. the waiting function can then do the storage of
		 * the values. Awesome. */
		tmp_sub_interval = PDU_BIG_INFO_SUB_INTERVAL_GET(binfo);
		tmp_bis_spacing = PDU_BIG_INFO_SPACING_GET(binfo);
		k_sem_give(&sem_biginfo);
	}
}

int pa_sync_create(struct broadcast *b) {
    uint32_t interval = BT_CONN_INTERVAL_TO_US(b->broadcaster_info.interval);
	struct bt_le_per_adv_sync_param create_params = {0};

	bt_addr_le_copy(&create_params.addr, &b->broadcaster_addr);
	create_params.options = 0;
	create_params.sid = b->broadcaster_info.sid;
	create_params.skip = 0;
    // retry 5 times
	create_params.timeout = (interval * 5) / (10 * USEC_PER_MSEC);

	return bt_le_per_adv_sync_create(&create_params, &b->broadcast_sync);
}

static void sync_cb(struct bt_le_per_adv_sync *sync, struct bt_le_per_adv_sync_synced_info *info) {
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));

	debug_printk("PER_ADV_SYNC[%u]: [DEVICE]: %s synced, "
	       "Interval 0x%04x (%u ms), PHY %s\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr,
	       info->interval, info->interval * 5 / 4, phy2str(info->phy));
}

static void term_cb(struct bt_le_per_adv_sync *sync, const struct bt_le_per_adv_sync_term_info *info) {
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));

	debug_printk("PER_ADV_SYNC[%u]: [DEVICE]: %s sync terminated\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr);
}

static void recv_cb(struct bt_le_per_adv_sync *sync, const struct bt_le_per_adv_sync_recv_info *info, struct net_buf_simple *buf) {
	char le_addr[BT_ADDR_LE_STR_LEN];
	char data_str[129];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));
	bin2hex(buf->data, buf->len, data_str, sizeof(data_str));

	debug_printk("PER_ADV_SYNC[%u]: [DEVICE]: %s, tx_power %i, "
	       "RSSI %i, CTE %u, data length %u, data: %s\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr, info->tx_power,
	       info->rssi, info->cte_type, buf->len, data_str);
}

static void biginfo_cb(struct bt_le_per_adv_sync *sync, const struct bt_iso_biginfo *biginfo) {
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(biginfo->addr, le_addr, sizeof(le_addr));

	debug_printk("BIG INFO[%u]: [DEVICE]: %s, sid 0x%02x, "
	       "num_bis %u, nse %u, interval 0x%04x (%u ms), "
	       "bn %u, pto %u, irc %u, max_pdu %u, "
	       "sdu_interval %u us, max_sdu %u, phy %s, "
	       "%s framing, %sencrypted\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr, biginfo->sid,
	       biginfo->num_bis, biginfo->sub_evt_count,
	       biginfo->iso_interval,
	       (biginfo->iso_interval * 5 / 4),
	       biginfo->burst_number, biginfo->offset,
	       biginfo->rep_count, biginfo->max_pdu, biginfo->sdu_interval,
	       biginfo->max_sdu, phy2str(biginfo->phy),
	       biginfo->framing ? "with" : "without",
	       biginfo->encryption ? "" : "not ");

    struct broadcast *b = get_broadcast_with_addr(biginfo->addr);
    if (b) {
        memcpy(&b->biginfo, biginfo, sizeof(*biginfo));
        b->has_biginfo = true;
    }
}

static struct bt_le_per_adv_sync_cb sync_callbacks = {
	.synced = sync_cb,
	.term = term_cb,
	.recv = recv_cb,
	.biginfo = biginfo_cb,
};

static bool scan_get_broadcaster_name(struct bt_data *data, void *user_data) {
    char *name_out = user_data;

	// this is the official broadcast name
	if (data->type == BT_DATA_BROADCAST_NAME) {
		strncpy(name_out, data->data, MIN(data->data_len, BROADCAST_MAX_NAME_LEN - 1));
        debug_printk("broadcast_name=%s\n", name_out);
		return false; // we found the name, stop parsing
	}

	// this supports non-audio ISO broadcasts
	if (data->type == BT_DATA_NAME_COMPLETE || data->type == BT_DATA_NAME_SHORTENED) {
		strncpy(name_out, data->data, MIN(data->data_len, BROADCAST_MAX_NAME_LEN - 1));
        debug_printk("bt name=%s\n", name_out);
		return false;
	}
	return true;
}

static bool scan_get_broadcast_id(struct bt_data *data, void *user_data) {
    uint32_t *broadcast_id = user_data;
	struct bt_uuid_16 adv_uuid;

    *broadcast_id = 0;

	if (data->type != BT_DATA_SVC_DATA16) 
		return true;

	if (data->data_len < BT_UUID_SIZE_16 + BT_AUDIO_BROADCAST_ID_SIZE)
		return true;

	if (!bt_uuid_create(&adv_uuid.uuid, data->data, BT_UUID_SIZE_16))
		return true;

	if (bt_uuid_cmp(&adv_uuid.uuid, BT_UUID_BROADCAST_AUDIO))
		return true;
	
	*broadcast_id = sys_get_le24(data->data + BT_UUID_SIZE_16);
    debug_printk("broadcast_id=%d\n", *broadcast_id);
	return false; // stop parsing
}

static struct broadcast* new_broadcast(uint32_t broadcast_id) {
    // initialize new broadcaster with ID
    if (cur_bcast < ARRAY_SIZE(broadcasts) - 1) {
		struct broadcast *b = &broadcasts[cur_bcast];
        cur_bcast++;
		return b;
    }

    printk("ERROR: can't store any more broadcasts. Try to increase BROADCAST_LIST_MAX_LEN.\n");
    return NULL;
}

static void broadcast_scan_recv(const struct bt_le_scan_recv_info *info, struct net_buf_simple *ad) {

    uint32_t broadcast_id = 0;
 	struct net_buf_simple buf_copy;
    char le_addr[BT_ADDR_LE_STR_LEN];

	net_buf_simple_clone(ad, &buf_copy);

	// we have a periodic advertiser
	if (info->interval) {
		bt_data_parse(&buf_copy, scan_get_broadcast_id, &broadcast_id);
		// if we know the broadcast already, we update the information
		struct broadcast *b = get_broadcast_with_addr(info->addr);
		// if we don't know it, we create a new broadcast
		if (b == NULL) {
			b = new_broadcast(broadcast_id);

			if (b == NULL) {
				printk("Yikes! We ran out of space for new broadcasts. Please increase BROADCAST_LIST_MAX_LEN\n");
				return 1;
			}

			bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));
			printk("Found new broadcaster with ID 0x%06X and addr %s and sid 0x%02X\n", broadcast_id,
			le_addr, info->sid);
		}

		// Store info for PA sync parameters
		memcpy(&b->broadcaster_info, info, sizeof(*info));
		bt_addr_le_copy(&b->broadcaster_addr, info->addr);
		b->broadcast_id = broadcast_id;

		net_buf_simple_clone(ad, &buf_copy);
		bt_data_parse(&buf_copy, scan_get_broadcaster_name, b->broadcaster_name);

		b->found = true;
	}
}

static void scan_get_biginfo_for_broadcast(struct broadcast *b) {

    int err;

    printk("Trying to obtain BIGInfo for broadcast %s (0x%x)\n", b->broadcaster_name, b->broadcast_id);

	bt_hci_iso_raw_dump_cb_register(scan_raw_get_biginfo_cb);

    err = pa_sync_create(b);
    if (err) {
        printk("Error syncing to periodic advertisments (0x%x)\n", err);
    }

    err = k_sem_take(&sem_biginfo, SEM_TIMEOUT);
    if (err) {
        printk("Error: Timeout in getting BIGInfo for stream %s(0x%x)\n", b->broadcaster_name, b->broadcast_id);
    }

	b->sub_interval = tmp_sub_interval;
	b->bis_spacing = tmp_bis_spacing;

    bt_le_per_adv_sync_delete(b->broadcast_sync);
	bt_hci_iso_raw_dump_cb_register(NULL);
}

static struct bt_le_scan_cb le_scan_cb = {
	.recv = broadcast_scan_recv,
};

int scan_on(const struct shell *sh, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

	int err;

	if (!bt_enabled) {
		shell_error(sh, "Bluetooth is not initialized yet, run `init` first!");
		return 1;
	}

	bt_le_scan_cb_register(&le_scan_cb);

    err = bt_le_scan_start(BT_LE_SCAN_ACTIVE, NULL);
	if (err != 0 && err != -EALREADY) {
		shell_print(sh, "Unable to start scanning: %d", err);
		return 0;
	}

    return 0;
}

int scan_off(const struct shell *sh, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

	int err;

	err = bt_le_scan_stop();
	if (err != 0) {
		shell_print(sh, "bt_le_scan_stop failed with %d, resetting", err);
	}

    return 0;
}

int scan_biginfo(const struct shell *sh, size_t argc, char **argv) {

    bt_le_per_adv_sync_cb_register(&sync_callbacks);

    if (argc == 1) {
        shell_print(sh, "Getting BIGInfo for all scanned broadcasts");
        for (int i = 0; i < ARRAY_SIZE(broadcasts); i++){
            struct broadcast *b = &broadcasts[i];

            if (b->found) {
                scan_get_biginfo_for_broadcast(b);
            }
        }
    } else if (argc == 2) {
		uint8_t broadcast_idx;
		struct broadcast *b;

		broadcast_idx = strtol(argv[1], NULL, 10);
		if (broadcast_idx < 0 || broadcast_idx > cur_bcast) {
			shell_error(sh, "Broadcast index %d out of bounds. Please specify something between 1 and %d. Check current broadcasts with `broadcast list`.", broadcast_idx, cur_bcast);
			return 1;
		}

		b = get_broadcast_at_idx(broadcast_idx);
		scan_get_biginfo_for_broadcast(b);
    }

    return 0;
}

int scan_list(const struct shell *sh, size_t argc, char **argv) {
    return broadcast_list(sh, argc, argv);
}