#include "clone.h"
#include "scan.h"

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/bluetooth/addr.h>


static int cmd_clone_start(const struct shell *sh, size_t argc, char **argv)
{
	struct sniffer_candidate cand;
	const char *tok = (argc >= 2) ? argv[1] : NULL;
	int err;

	err = sniffer_scan_lookup(tok, &cand);
	if (err) {
		if (tok == NULL) {
			shell_error(sh, "no broadcast candidates, `scan on` first");
		} else {
			shell_error(sh, "no matching candidate for '%s', "
					"`scan list` to see options", tok);
		}
		return err;
	}

	char addr_str[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(&cand.addr, addr_str, sizeof(addr_str));
	shell_print(sh, "clone: source %s sid=%u name='%s' bid=%s bcode=%s",
		    addr_str, cand.sid, cand.name,
		    cand.has_broadcast_id ? "set" : "-",
		    cand.bcode_len ? "set" : "-");

	err = clone_start(&cand, sh);
	if (err) {
		shell_error(sh, "clone start failed: %d", err);
		return err;
	}
	shell_print(sh, "clone: running, `clone stop` to tear down");
	return 0;
}

static int cmd_clone_stop(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!clone_is_active()) {
		shell_warn(sh, "clone not running");
		return 0;
	}
	(void)clone_stop();
	shell_print(sh, "clone stopped");
	return 0;
}

static int cmd_clone_status(const struct shell *sh, size_t argc, char **argv)
{
	char line[128];

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	clone_status(line, sizeof(line));
	shell_print(sh, "%s", line);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_clone,
	SHELL_CMD_ARG(start, NULL,
		      "[<target>]: rebroadcast target's Auracast as a "
		      "0x41-fill BIG at 2x PA rate",
		      cmd_clone_start, 1, 1),
	SHELL_CMD(stop,   NULL, "Tear down clone",   cmd_clone_stop),
	SHELL_CMD(status, NULL, "Show clone state",  cmd_clone_status),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(clone, &sub_clone,
		   "clone: [WIP] Clone an Auracast stream (with bogus data)",
		   NULL);

