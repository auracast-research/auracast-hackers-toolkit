#ifndef SNIFFER_CLI_H_
#define SNIFFER_CLI_H_

enum sniffer_mode {
	SNIFFER_MODE_M1 = 0,  /* HCI ISO Data (pcap DLT 187, LINKTYPE_BLUETOOTH_HCI_H4)          */
	SNIFFER_MODE_M2 = 1,  /* Raw LL PDU  (pcap DLT 256, LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR)  */
};

int sniffer_cli_init(void);

enum sniffer_mode sniffer_cli_mode(void);

#endif /* SNIFFER_CLI_H_ */
