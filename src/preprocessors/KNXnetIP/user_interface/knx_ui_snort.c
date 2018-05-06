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
#include "knx_ui_config.h"

/*
 * GLOBAL keywords.
 */
#define KNX_PROGRAMMING 			"programming"
#define KNX_PHYSICAL_ADDRESSING 	"physical_address"

int KNXnetIPInitializeGlobalConfig(KNXNETIP_CONF *config, char *errstr, int errstrlen)
{
	int ret;

	if (config == NULL)
	{
		snprintf(errstr, errstrlen, "Global configuration is NULL.");
		return -1;
	}

	ret = knx_ui_config_init_global_conf(config);
	if (ret) {
		snprintf(errstr, errstrlen, "Error initializing Global Configuration.");
		return -1;
	}

	return 0;
}

int KNXnetIPProcessGlobalConf(KNXNETIP_CONF *GlobalConf, char *errstr, int errstrlen)
{
	int ret;
	char *pcToken;
	int iTokens = 0;

	while ((pcToken = strtok(NULL, CONF_SEPARATORS)) != NULL)
	{
		iTokens = 1;

		if(!strcmp(KNX_PROGRAMMING, pcToken))
		{
			GlobalConf->pdata[GLOBAL_CONFIG]->bProgramming = true;
		}
		else if(!strcmp(KNX_PHYSICAL_ADDRESSING, pcToken))
		{
			GlobalConf->pdata[GLOBAL_CONFIG]->bPhysicalAddressing = true;
		}
		else
		{
			;
		}

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
		knx_ui_append_conf(GlobalConf);
		GlobalConf->pdata[GlobalConf->length-1] = ServerConf;

	}

	KNXnetIPPrintServerConf(ServerConf);
	ret = 0;

cleanup:
	if (pIpAddressListCopy)
	{
		free(pIpAddressListCopy);
	}
	return ret;

}

int KNXnetIPPrintGlobalConf(KNXNETIP_CONF *GlobalConf)
{
	LogMessage("KNXnet/IP Config:\n");
	LogMessage("    GLOBAL_CONFIG\n");
	LogMessage("      Detect device programming:       %3s\n", GlobalConf->pdata[GLOBAL_CONFIG]->bProgramming ? "Yes" : "No");
	LogMessage("      Detect physical addressing:      %3s\n", GlobalConf->pdata[GLOBAL_CONFIG]->bPhysicalAddressing ? "Yes" : "No");

	return 0;
}

int KNXnetIPPrintServerConf(KNXNETIP_SERVER_CONF *ServerConf)
{
	return 0;
}
