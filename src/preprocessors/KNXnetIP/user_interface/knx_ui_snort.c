/*
 * knx_ui_snort.c
 *
 *  Created on: May 6, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knx_ui_snort.h"
/*
 * GLOBAL keywords.
 */
#define KNX_SERVER_IP				"ip"
#define KNX_SERVER_PORT				"port"
#define KNX_SERVICE					"service"
#define KNX_PROGRAMMING 			"programming"
#define KNX_INDIVIDUAL_ADDRESSING 	"individual_address"
#define NO_INDIVIDUAL_ADDRESSING	"!individual_address"
#define KNX_GROUP_ADDRESSING		"group_address"
#define NO_GROUP_ADDRESSING			"!group_address"
#define KNX_PAYLOAD					"payload"
#define NO_KNX_PAYLOAD				"!payload"
#define KNX_GROUP_ADDRESS_FILE		"file"

int KNXnetIPCopyGlobalConf(KNXNETIP_CONF *config)
{
	KNXNETIP_SERVER_CONF *from, *to;

	from = config->pdata[GLOBAL_CONFIG];
	to = config->pdata[config->length-1];

	to->bIndividualAddressing = from->bIndividualAddressing;
	to->bProgramming = from->bProgramming;
	to->bPayload = from->bPayload;

	// FIXIT: full copy of config not supported, as freeing
	// memory results in multiple free's in current implementation of
	// KNXnetIPCleanExit().
//	if (from->filename) {
//		to->filename = from->filename;
//	}
//
//	if (from->ip.length != 0) {
//		to->ip = from->ip;
//	}
//
//	if (from->port.length != 0) {
//		to->port = from->port;
//	}
//
//	if (from->service.length != 0) {
//		to->service = from->service;
//	}
//
//	if (from->group_address.length != 0) {
//		to->group_address = from->group_address;
//	}

	return 0;
}

int KNXnetIPInitializeGlobalConfig(KNXNETIP_CONF *config, char *errstr, int errstrlen)
{
	int ret;

	if (config == NULL)
	{
		snprintf(errstr, errstrlen, "Global configuration is NULL.");
		return -1;
	}

	ret = knx_ui_append_conf(config);
	if (ret)
	{
		snprintf(errstr, errstrlen, "Error initializing configuration.");
		return -1;
	}

	return 0;
}

int KNXnetIPInitializeServerConfig(KNXNETIP_CONF *config, char *errstr, int errstrlen)
{
	int ret;

	if ((ret = KNXnetIPInitializeGlobalConfig(config, errstr, errstrlen)) == 0)
	{
		KNXnetIPCopyGlobalConf(config);
	}

	return ret;
}

int KNXnetIPProcessConf(struct _SnortConfig *sc, KNXNETIP_CONF *config, char *errstr, int errstrlen)
{
//	int ret;
	char *pcToken;
	boolean bTokens = false;
	uint8_t entry = config->length - 1;

	while ((pcToken = strtok(NULL, CONF_SEPARATORS)) != NULL)
	{
		bTokens = true;

		/* Detect Programming */
		if(!strcmp(KNX_PROGRAMMING, pcToken))
		{
			config->pdata[entry]->bProgramming = true;
		}

		/* Detect Physical Addressing */
		else if(!strcmp(KNX_INDIVIDUAL_ADDRESSING, pcToken))
		{
			config->pdata[entry]->bIndividualAddressing = true;
		}

		else if(!strcmp(NO_INDIVIDUAL_ADDRESSING, pcToken))
		{
			config->pdata[entry]->bIndividualAddressing = false;
		}

		/* Detect Group Addresses */
		else if(!strcmp(KNX_GROUP_ADDRESSING, pcToken))
		{
			config->pdata[entry]->bGroupAddressing = true;
		}

		else if(!strcmp(NO_GROUP_ADDRESSING, pcToken))
		{
			config->pdata[entry]->bGroupAddressing = false;
		}

		/* Log Payload */
		else if(!strcmp(KNX_PAYLOAD, pcToken))
		{
			config->pdata[entry]->bPayload = true;
		}

		else if(!strcmp(NO_KNX_PAYLOAD, pcToken))
		{
			config->pdata[entry]->bPayload = false;
		}

		else if(!strcmp(KNX_GROUP_ADDRESS_FILE, pcToken))
		{
			knx_ui_load_filename(config);
			knx_ui_load_group_address(config);
		}

		else if(!strcmp(KNX_SERVER_IP, pcToken))
		{
			knx_ui_load_ip(config);
		}

		else if(!strcmp(KNX_SERVER_PORT, pcToken))
		{
			knx_ui_load_ports(config);
		}

		else if(!strcmp(KNX_SERVICE, pcToken))
		{
			knx_ui_load_services(config);
		}

		/* Not supported/recognized option */
		else
		{
			;
		}
	}

	if (!bTokens)
	{
		SnortSnprintf(errstr, errstrlen, "No tokens to '%s' configuration.", config->length == 1 ? GLOBAL : SERVER);
		return -1;
	}

	return 0;
}

static int KNXnetIPPrintConf(KNXNETIP_SERVER_CONF *s)
{
	LogMessage("      Detect device programming:       %s\n", s->bProgramming ? "Yes" : "No");
	LogMessage("      Detect individual addressing:    %s\n", s->bIndividualAddressing ? "Yes" : "No");

	if (s->ip.length > 0) {
		knx_ui_print_ip_addresses(LogMessage, &s->ip);
	}
	if (s->port.length > 0) {
		knx_ui_print_ports(LogMessage, &s->port);
	}
	if (s->service.length > 0) {
		knx_ui_print_services(LogMessage, &s->service);
	}
	if (s->filename != NULL) {
		LogMessage("      Detect group addresses:          %s\n", s->bIndividualAddressing ? "Yes" : "No");
		LogMessage("      Group Address File:              %s\n", s->filename);
		knx_ui_print_group_addresses(LogMessage, &s->group_address);
	}
	return 0;
}

int KNXnetIPPrintGlobalConf(KNXNETIP_CONF *config)
{
	LogMessage(KNX_UI_BACKGROUND_COLOR);
	LogMessage(KNX_UI_FOREGROUND_COLOR);

	uint8_t entry = config->length - 1;
	KNXNETIP_SERVER_CONF *s = config->pdata[entry];

	LogMessage("KNXnet/IP Config:\n");
	LogMessage("  GLOBAL_CONFIG\n");
	KNXnetIPPrintConf(s);

	LogMessage(KNX_UI_RESET_COLOR);
	return 0;
}

int KNXnetIPPrintServerConf(KNXNETIP_CONF *config)
{
	LogMessage(KNX_UI_BACKGROUND_COLOR);
	LogMessage(KNX_UI_FOREGROUND_COLOR);

	uint8_t entry = config->length - 1;
	KNXNETIP_SERVER_CONF *s = config->pdata[entry];

	LogMessage("    SERVER_CONFIG\n");
	KNXnetIPPrintConf(s);

	LogMessage(KNX_UI_RESET_COLOR);
	return 0;
}
