/*
 * spp_knxnetip.c
 *
 *  Created on: May 6, 2018
 *      Author: alija
 */
#include "preprocids.h"
#include "plugbase.h"
#include "decode.h"
#include "session_api.h"
#include "snort_debug.h"
#include "spp_knxnetip.h"
#include "knxnetip.h"

#define GLOBAL_KEYWORD "knxnetip"
#define SERVER_KEYWORD "knxnetip_server"

static void KNXnetIPInit(struct _SnortConfig *sc, char *args);
static void KNXnetIPProcess(Packet *p, void *ctx);

#ifdef SNORT_RELOAD
	static void KNXnetIPReloadGlobal(struct _SnortConfig *sc, char *args, void **new_config);
	static void KNXnetIPReload(struct _SnortConfig *sc, char *args, void **new_config);
	static int KNXnetIPReloadVerify(struct _SnortConfig *sc, void *swap_config);
	static void * KNXnetIPReloadSwap(struct _SnortConfig *sc, void *swap_config);
	static void KNXnetIPReloadSwapFree(void *data);
#endif

static void KNXnetIPInit(struct _SnortConfig *sc, char *args)
{
	AddFuncToPreprocList(sc, KNXnetIPProcess, PRIORITY_APPLICATION, PP_KNXNETIP, PROTO_BIT__UDP);
	session_api->enable_preproc_all_ports( sc, PP_KNXNETIP, PROTO_BIT__UDP );
}

void SetupKNXnetIP(void)
{
#ifndef SNORT_RELOAD
	RegisterProprocessor(GLOBAL_KEYWORD, KNXnetIPInit);
	RegisterPreprocessor(SERVER_KEYWORD, KNXnetIPInit);
#else
	RegisterPreprocessor(GLOBAL_KEYWORD, KNXnetIPInit, KNXnetIPReloadGlobal,
						 KNXnetIPReloadVerify, KNXnetIPReloadSwap,
						 KNXnetIPReloadSwapFree);
	RegisterPreprocessor(SERVER_KEYWORD, KNXnetIPInit,
						 KNXnetIPReload, NULL, NULL, NULL);
#endif
	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: KNXnet/IP is setup...\n"););
}

static void KNXnetIPProcess(Packet *p, void *context)
{
	dissect_knxnetip(p->data);
}


#ifdef SNORT_RELOAD

static void KNXnetIPReloadGlobal(struct _SnortConfig *sc, char *args, void **new_config) { }
static void KNXnetIPReload(struct _SnortConfig *sc, char *args, void **new_config) { }
static int KNXnetIPReloadVerify(struct _SnortConfig *sc, void *swap_config) { return 0; }
static void *KNXnetIPReloadSwap(struct _SnortConfig *sc, void *swap_config) { return swap_config; }
static void KNXnetIPReloadSwapFree(void *data) { }
#endif
