#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/audio/lc3.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/audio/audio.h>
#include <zephyr/bluetooth/audio/bap.h>
#include <zephyr/bluetooth/audio/pacs.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gap.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/hci_types.h>
#include <zephyr/bluetooth/iso.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/net_buf.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <zephyr/shell/shell.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_audio.h>
#include <zephyr/sys/ring_buffer.h>

#define BROADCAST_NAME_LEN                  sizeof(CONFIG_TARGET_BROADCAST_NAME) + 1
#define BROADCAST_MAX_NAME_LEN              128
#define BROADCAST_LIST_MAX_LEN              10
#define SEM_TIMEOUT                         K_SECONDS(2)
#define PA_SYNC_INTERVAL_TO_TIMEOUT_RATIO   5 /* Set the timeout relative to interval */

#define debug_printk(format,args...)        \
                  if (debug) {      \
                      printk(format, ## args);    \
                  }


struct broadcast {
    bool found;
    uint32_t broadcast_id;
    bt_addr_le_t broadcaster_addr;
    char broadcaster_name[BROADCAST_MAX_NAME_LEN];
    bool has_biginfo;
    struct bt_iso_biginfo biginfo;
    struct bt_le_per_adv_sync *broadcast_sync;
    struct bt_le_scan_recv_info broadcaster_info;
    /* we have to capture BIS spacing and subevent interval from the raw PDU because it
     * is not forwarded in the BIGInfo HCI event */
    uint32_t sub_interval;
    uint32_t bis_spacing;
};

/* this is taken from pdu.h to work without pdu_biginfo struct definition */
#define PDU_BIG_INFO_SPACING_GET(bi) \
	util_get_bits(bi+8, 0, 20)
#define PDU_BIG_INFO_SUB_INTERVAL_GET(bi) \
	util_get_bits(bi+5, 0, 20)

// Scan Commands
int scan_on(const struct shell *sh, size_t argc, char **argv);
int scan_off(const struct shell *sh, size_t argc, char **argv);
int scan_list(const struct shell *sh, size_t argc, char **argv);
int scan_biginfo(const struct shell *sh, size_t argc, char **argv);

// Broadcast Commands
int broadcast_list(const struct shell *sh, size_t argc, char **argv);
int broadcast_dump(const struct shell *sh, size_t argc, char **argv);
int broadcast_bisquit(const struct shell *sh, size_t argc, char **argv);
int broadcast_hijack(const struct shell *sh, size_t argc, char **argv);

extern bool bt_enabled;
extern bool debug;
extern struct broadcast broadcasts[BROADCAST_LIST_MAX_LEN];
extern uint8_t cur_bcast;
extern struct k_sem sem_biginfo;

struct broadcast* get_broadcast_at_idx(const uint8_t idx);
struct broadcast* get_broadcast_with_id(uint32_t broadcast_id);
struct broadcast* get_broadcast_with_addr(const bt_addr_le_t *addr);
int pa_sync_create(struct broadcast *b);

void set_active_broadcast_prompt(struct broadcast *b);
void remove_active_broadcast_prompt();
struct broadcast *get_active_broadcast();

bool is_substring(const char *substr, const char *str);
const char *phy2str(uint8_t phy);