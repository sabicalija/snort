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
#define KNX_SERVER_IP				"server"
#define KNX_PROGRAMMING 			"programming"
#define KNX_PHYSICAL_ADDRESSING 	"physical_address"
#define NO_PHYSICAL_ADDRESSING		"!physical_address"
#define KNX_GROUP_ADDRESS_FILE		"file"

int KNXnetIPCopyGlobalConf(KNXNETIP_CONF *config)
{
	KNXNETIP_SERVER_CONF *from, *to;

	from = config->pdata[GLOBAL_CONFIG];
	to = config->pdata[config->length-1];

	to->bPhysicalAddressing = from->bPhysicalAddressing;
	to->bProgramming = from->bProgramming;

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
	int ret;
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
		else if(!strcmp(KNX_PHYSICAL_ADDRESSING, pcToken))
		{
			config->pdata[entry]->bPhysicalAddressing = true;
		}

		else if(!strcmp(NO_PHYSICAL_ADDRESSING, pcToken))
		{
			config->pdata[entry]->bPhysicalAddressing = false;
		}

		else if(!strcmp(KNX_GROUP_ADDRESS_FILE, pcToken))
		{
			knx_ui_load_filename(config);
			knx_ui_load_group_address(config);
		}

		else if(!strcmp(KNX_SERVER_IP, pcToken))
		{

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


int KNXnetIPProcessUniqueServerConf(struct _SnortConfig *sc, KNXNETIP_CONF *GlobalConf, char *errstr, int errstrlen)
{
	char *pcToken;
	char *pIpAddressList = NULL;
	char *pIpAddressListCopy = NULL;
	char *brkt = NULL;
	sfcidr_t Ip;
	KNXNETIP_SERVER_CONF *ServerConf = NULL;
	int ret;

	pcToken = strtok(NULL, CONF_SEPARATORS);
	if(pcToken == NULL)
	{
		SnortSnprintf(errstr, errstrlen, "No arguments to '%s' token.", SERVER);
		ret = -1;
		goto cleanup;
	}

	/*
	 * Convert string to IP address.
	 */
	if(strcmp(KNX_START_IPADDR_LIST, pcToken) == 0)
	{
		/* Process IP list */
		if ((pIpAddressList = strtok(NULL, KNX_END_IPADDR_LIST)) == NULL)
		{
			SnortSnprintf(errstr, errstrlen, "Invalid IP Address in '%s' token.", SERVER);
			ret = -1;
			goto cleanup;
		}
	}
	else
	{
		/* Process IP */
		pIpAddressList = pcToken;
	}

	/* Copy IP address(es) */
	pIpAddressListCopy = strdup(pIpAddressList);
	if (pIpAddressListCopy == NULL)
	{
		SnortSnprintf(errstr, errstrlen, "Could not allocate memory for server configuration.");
		ret = -1;
		goto cleanup;
	}

	for (pcToken = strtok_r(pIpAddressList, CONF_SEPARATORS, &brkt);
		 pcToken;
		 pcToken = strtok_r(NULL, CONF_SEPARATORS, &brkt))
	{
		if (sfip_pton(pcToken, &Ip) != SFIP_SUCCESS)
		{
			SnortSnprintf(errstr, errstrlen, "Invalid IP to '%s' token.", SERVER);
			goto cleanup;
		}

		ServerConf = (KNXNETIP_SERVER_CONF *)calloc(1, sizeof(KNXNETIP_SERVER_CONF));
		if (ServerConf == NULL)
		{
			SnortSnprintf(errstr, errstrlen, "Could not allocate memory for server configuration.");
			goto cleanup;
		}


//		knx_ui_add_server_ip()
		/*
		 * FIXIT:
		 *  - append IPs
		 *  - append Ports
		 *  - append Services
		 *  - append Group Addresses
		 *
		 *  - append file name
		 *  - process file (group address)
		 *
		 *
		 *  optional:
		 *  - create lookup table
		 */
		knx_ui_append_server_conf(GlobalConf);
		GlobalConf->pdata[GlobalConf->length-1] = ServerConf;

	}

//	KNXnetIPPrintServerConf(ServerConf);
	ret = 0;

cleanup:
	if (pIpAddressListCopy)
	{
		free(pIpAddressListCopy);
	}
	return ret;

}

static int KNXnetIPPrintConf(KNXNETIP_CONF *config)
{
	uint8_t entry = config->length - 1;
	LogMessage("      Detect device programming:       %3s\n", config->pdata[entry]->bProgramming ? "Yes" : "No");
	LogMessage("      Detect physical addressing:      %3s\n", config->pdata[entry]->bPhysicalAddressing ? "Yes" : "No");
	return 0;
}

int KNXnetIPPrintGlobalConf(KNXNETIP_CONF *config)
{
	LogMessage("KNXnet/IP Config:\n");
	LogMessage("  GLOBAL_CONFIG\n");
	KNXnetIPPrintConf(config);
	return 0;
}

int KNXnetIPPrintServerConf(KNXNETIP_CONF *config)
{
	uint8_t entry = config->length - 1;
	KNXNETIP_SERVER_CONF *srvcfg = config->pdata[entry];

	LogMessage("    SERVER_CONFIG\n");
	KNXnetIPPrintConf(config);
	LogMessage("      Group Address File:              %s\n", srvcfg->filename);
	knx_ui_print_group_addresses(LogMessage, &srvcfg->group_address);

	return 0;
}
