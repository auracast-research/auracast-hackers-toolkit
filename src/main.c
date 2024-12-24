#include "auracast_hackers_toolkit.h"

bool bt_enabled = false;
bool debug = false;

static struct shell *gshell;
struct broadcast *active_broadcast = NULL;
uint32_t broadcaster_broadcast_id;

static int init(const struct shell *sh, size_t argc, char **argv) {

	ARG_UNUSED(argc);
    ARG_UNUSED(argv);

	int err;

	if (bt_enabled) {
		shell_error(sh, "Bluetooth is already initialized!");
		return 1;
	}

	err = bt_enable(NULL);
	if (err) {
		shell_print(sh, "Bluetooth enable failed (err %d)", err);
		return err;
	}

	shell_print(sh, "Bluetooth initialized");

	// set global reference for shell - not sure if this is good practice
	gshell = sh;

	bt_enabled = true;
	return 0;
}

static int reset(const struct shell *sh, size_t argc, char **argv) {
	ARG_UNUSED(argc);
    ARG_UNUSED(argv);

	int err;

	shell_info(sh, "Resetting application.");

	memset(broadcasts, 0x00, sizeof(broadcasts));
	cur_bcast = 0;

	broadcaster_broadcast_id = BT_BAP_INVALID_BROADCAST_ID;

	return 0;
}

static uint16_t interval_to_sync_timeout(uint16_t pa_interval)
{
	uint16_t pa_timeout;

	if (pa_interval == BT_BAP_PA_INTERVAL_UNKNOWN) {
		/* Use maximum value to maximize chance of success */
		pa_timeout = BT_GAP_PER_ADV_MAX_TIMEOUT;
	} else {
		uint32_t interval_ms;
		uint32_t timeout;

		/* Add retries and convert to unit in 10's of ms */
		interval_ms = BT_GAP_PER_ADV_INTERVAL_TO_MS(pa_interval);
		timeout = (interval_ms * PA_SYNC_INTERVAL_TO_TIMEOUT_RATIO) / 10;

		/* Enforce restraints */
		pa_timeout = CLAMP(timeout, BT_GAP_PER_ADV_MIN_TIMEOUT, BT_GAP_PER_ADV_MAX_TIMEOUT);
	}

	return pa_timeout;
}

void set_active_broadcast_prompt(struct broadcast *b) {
	
	int err;

	active_broadcast = b;

	if (gshell) {
		char prompt[40];
		snprintf(prompt, 40, "broadcast [ID=0x%x]:~$ ", b->broadcast_id);
		err = shell_prompt_change(gshell, prompt);
		if (err) {
			printk("error setting shell prompt: %d\n", err);
		}
	}
}

void remove_active_broadcast_prompt() {
	active_broadcast = NULL;

	if (gshell) {
		shell_prompt_change(gshell, "auracast-hackers-toolkit:~$ ");
	}
}

struct broadcast *get_active_broadcast() {
	return active_broadcast;
}

int debug_on(const struct shell *sh, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
    ARG_UNUSED(sh);
	debug = true;
	shell_print(sh, "Debug output enabled");
}

int debug_off(const struct shell *sh, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
    ARG_UNUSED(sh);
	debug = false;
	shell_print(sh, "Debug output disabled");
}

int debug_handler(const struct shell *sh, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
	shell_print(sh, "Debug is %s", debug ? "enabled" : "disabled");
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_scan,
        SHELL_CMD(on, NULL, "Start scanning.", scan_on),
        SHELL_CMD(off, NULL, "Stop scanning.", scan_off),
        SHELL_CMD(biginfo, NULL, "Obtain BIGInfo for all broadcasts or a given broadcast.", scan_biginfo),
        SHELL_CMD(list, NULL, "List scanned broadcasts.", scan_list),
        SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_broadcast,
        SHELL_CMD(list, NULL, "List scanned broadcasts.", broadcast_list),
        SHELL_CMD(dump, NULL, "Dump Raw BIS PDUs and BIGInfo packets.", broadcast_dump),
        SHELL_CMD(bisquit, NULL, "Run the bisquit attack against broadcast", broadcast_bisquit),
        SHELL_CMD(hijack, NULL, "Hijack broadcast", broadcast_hijack),
        SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_debug,
        SHELL_CMD(on, NULL, "Debug on.", debug_on),
        SHELL_CMD(off, NULL, "Debug off.", debug_off),
        SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(init, NULL, "Initialize Bluetooth", init);
SHELL_CMD_REGISTER(reset, NULL, "Reset Application (not controller)", reset);
SHELL_CMD_REGISTER(scan, &sub_scan, "Scan for Auracast Broadcasts", NULL);
SHELL_CMD_REGISTER(broadcast, &sub_broadcast, "Broadcast commands", NULL);
SHELL_CMD_REGISTER(debug, &sub_debug, "Debug Options (on/off)", debug_handler);

int main(void) {}