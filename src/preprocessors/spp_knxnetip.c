/*
 * spp_knxnetip.c
 *
 *  Created on: May 6, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode.h"
#include "plugbase.h"
#include "snort_debug.h"
#include "parser.h"

#include "spp_knxnetip.h"
#include "knxnetip.h"
#include "knx_ui_config.h"
#include "knx_ui_snort.h"

//#include "preprocids.h"

//# pp spec.

//# snort/profiler/mstring/...
#include "sp_preprocopt.h"

#ifdef TARGET_BASED
#include "session_api.h"
#endif

//# policy
//#include "sfPolicy.h"
//#include "file_api.h"

//# reload

//# oappid

/*
 * Preprocessor initialization
 */

// DEFINES


//const char *PROTOCOL_NAME = "KNXnet/IP";

/* Length of the error string buffer. */
#define ERRSTRLEN 1000

// EXT. GLOBALS
/* Variables that we need from Snort to log errors correctly, etc.. */
extern char *file_name;
extern int file_line;

// GLOBALS
/* Note: This is the only way to work with Snort preprocessors.
 * User configuration, that must be kept between the `Init` and
 * `Process` function, has to use global variables, as there is
 * no further interaction between the two.
 */
tSfPolicyUserContextId knx_config = NULL;

// PROTOTYPES
static void KNXnetIPInit(struct _SnortConfig *sc, char *args);
static void KNXnetIPCleanExit(int signal, void *data);
static void KNXnetIPProcess(Packet *p, void *ctx);

static int KNXnetIPEncodeInit(struct _SnortConfig *sc, char *name, char *parameters, void **dataPtr);
static int KNXnetIPEncodeEval(void *p, const uint8_t **cursor, void *dataPtr);
static void KNXnetIPEncodeCleanup(void *dataPtr);
static void KNXnetIPRegisterRuleOptions(struct _SnortConfig *sc);

#ifdef SNORT_RELOAD
	static void KNXnetIPReloadGlobal(struct _SnortConfig *sc, char *args, void **new_config);
	static void KNXnetIPReload(struct _SnortConfig *sc, char *args, void **new_config);
	static int KNXnetIPReloadVerify(struct _SnortConfig *sc, void *swap_config);
	static void * KNXnetIPReloadSwap(struct _SnortConfig *sc, void *swap_config);
	static void KNXnetIPReloadSwapFree(void *data);
#endif

static void KNXnetIPInit(struct _SnortConfig *sc, char *args)
{
	char errstr[ERRSTRLEN];
	int errstrlen = ERRSTRLEN;
	int ret;
	char *pcToken;
	KNXNETIP_CONF *pPolicyConfig = NULL;
	tSfPolicyId policy_id = getParserPolicy(sc);

	if ((args == NULL) || (strlen(args) == 0))
	{
		ParseError("No arguments to KNXnetIP configuration.");
	}

	/* Find out what is getting configured */
	pcToken = strtok(args, CONF_SEPARATORS);
	if (pcToken == NULL)
	{
		FatalError("%s(%d)strtok returned NULL when it should not.",
				   __FILE__, __LINE__);
	}

	if (knx_config == NULL)
	{
		knx_config = sfPolicyConfigCreate();

		/* Add cleanup function(s) to the appropriate list */
		AddFuncToPreprocCleanExitList(KNXnetIPCleanExit, NULL, PRIORITY_APPLICATION, PP_KNXNETIP);
	}

	/*
	 * Global Configuration Processing
	 */
	sfPolicyUserPolicySet(knx_config, policy_id);
	pPolicyConfig = (KNXNETIP_CONF *)sfPolicyUserDataGetCurrent(knx_config);
	if (pPolicyConfig == NULL)
	{
		if (strcasecmp(pcToken, GLOBAL) != 0)
		{
			ParseError("Must configure the knxnetip global configuration first.");

		}

		KNXnetIPRegisterRuleOptions(sc);

		pPolicyConfig = (KNXNETIP_CONF *)SnortAlloc(sizeof(KNXNETIP_CONF));
		if (pPolicyConfig == NULL)
		{
			ParseError("KNXnetIP preprocessor: memory allocate failed.\n");
		}

		sfPolicyUserDataSetCurrent(knx_config, pPolicyConfig);

		ret = KNXnetIPInitializeGlobalConfig(pPolicyConfig, errstr, errstrlen);

		if (ret == 0)
		{
			ret = KNXnetIPProcessConf(sc, pPolicyConfig, errstr, errstrlen);

			if (ret == 0)
			{
				KNXnetIPPrintGlobalConf(pPolicyConfig);

				AddFuncToPreprocList(sc, KNXnetIPProcess, PRIORITY_APPLICATION, PP_KNXNETIP, PROTO_BIT__UDP);
				session_api->enable_preproc_all_ports( sc, PP_KNXNETIP, PROTO_BIT__UDP );
			}
		}

	}
	/*
	 * Server Configuration Processing
	 */
	else
	{
		if (strcasecmp(pcToken, SERVER) != 0)
		{
			if (strcasecmp(pcToken, GLOBAL) != 0)
			{
				ParseError("Must configure the knxnetip global configuration first.");
			}
			else
			{
				ParseError("Invalid knxnetip token: %s.", pcToken);
			}
		}

		ret = KNXnetIPInitializeServerConfig(pPolicyConfig, errstr, errstrlen);

		if (ret == 0)
		{
			ret = KNXnetIPProcessConf(sc, pPolicyConfig, errstr, errstrlen);

			if (ret == 0)
			{
				KNXnetIPPrintServerConf(pPolicyConfig);
			}
		}


	}
}



static int KNXnetIPEncodeInit(struct _SnortConfig *sc, char *name, char *parameters, void **dataPtr)
{
	return 0;
}

static int KNXnetIPEncodeEval(void *p, const uint8_t **cursor, void *dataPtr)
{
	return DETECTION_OPTION_NO_MATCH;
}

static void KNXnetIPEncodeCleanup(void *dataPtr)
{

}

static void KNXnetIPRegisterRuleOptions(struct _SnortConfig *sc)
{
	RegisterPreprocessorRuleOption(sc, "knxnetip_encode", &KNXnetIPEncodeInit,
									&KNXnetIPEncodeEval, &KNXnetIPEncodeCleanup, NULL,
									NULL, NULL, NULL);
}



void SetupKNXnetIP(void)
{
#ifndef SNORT_RELOAD
	RegisterProprocessor(KNXNETIP_CONF_KEYWORD, KNXnetIPInit);
//	RegisterPreprocessor(KNXNETIP_CONF_SERVER_KEYWORD, KNXnetIPInit);
#else
	RegisterPreprocessor(KNXNETIP_CONF_KEYWORD, KNXnetIPInit, KNXnetIPReloadGlobal,
						 KNXnetIPReloadVerify, KNXnetIPReloadSwap,
						 KNXnetIPReloadSwapFree);
//	RegisterPreprocessor(KNXNETIP_CONF_SERVER_KEYWORD, KNXnetIPInit,
//						 KNXnetIPReload, NULL, NULL, NULL);
#endif
	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: KNXnet/IP is setup...\n"););
}

static void KNXnetIPProcess(Packet *p, void *context)
{
	dissect_knxnetip(p->data);
}

static void KNXnetIPCleanExit(int signal, void *data)
{
	KNXNETIP_CONF *pPolicyConfig = (KNXNETIP_CONF *)sfPolicyUserDataGetCurrent(knx_config);

	for (int i = 0; i < pPolicyConfig->length; i++)
	{
		// Ip Addresses
		KNXNETIP_IPS *ipaddr = &pPolicyConfig->pdata[i]->ip;
		for (int j = 0; j < ipaddr->length; j++)
		{
			if (ipaddr->pdata[j])
			{
				free(ipaddr->pdata[j]);
			}
		}

		if (ipaddr->pdata)
		{
			free(ipaddr->pdata);
		}

		// Ports
		KNXNETIP_PORTS *ports = &pPolicyConfig->pdata[i]->port;
		for (int j = 0; j < ports->length; j++)
		{
			if (ports->pdata[j])
			{
				free(ports->pdata[j]);
			}
		}

		if (ports->pdata)
		{
			free(ports->pdata);
		}

		// Group Addresses
		KNXNETIP_GRPADDRS *grpaddr = &pPolicyConfig->pdata[i]->group_address;
		for (int j = 0; j < grpaddr->length; j++)
		{
			if (grpaddr->pdata[j])
			{
				free(grpaddr->pdata[j]);
			}
		}

		if (grpaddr->pdata)
		{
			free(grpaddr->pdata);
		}

		// Server Configuration
		if (pPolicyConfig->pdata[i])
		{
			free(pPolicyConfig->pdata[i]);
		}
	}

	if (pPolicyConfig->pdata)
	{
		free(pPolicyConfig->pdata);
	}
}


#ifdef SNORT_RELOAD

static void KNXnetIPReloadGlobal(struct _SnortConfig *sc, char *args, void **new_config) { }
static void KNXnetIPReload(struct _SnortConfig *sc, char *args, void **new_config) { }
static int KNXnetIPReloadVerify(struct _SnortConfig *sc, void *swap_config) { return 0; }
static void *KNXnetIPReloadSwap(struct _SnortConfig *sc, void *swap_config) { return swap_config; }
static void KNXnetIPReloadSwapFree(void *data) { }
#endif
