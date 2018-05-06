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

static void KNXnetIPInit(struct _SnortConfig *sc, char *args);
static void KNXnetIPProcess(Packet *p, void *ctx);


static void KNXnetIPInit(struct _SnortConfig *sc, char *args)
{
	AddFuncToPreprocList(sc, KNXnetIPProcess, PRIORITY_APPLICATION, PP_KNXNETIP, PROTO_BIT__UDP);
	session_api->enable_preproc_all_ports( sc, PP_KNXNETIP, PROTO_BIT__UDP );
}

static void KNXnetIPProcess(Packet *p, void *ctx)
{
	int i = 0;
	dissect_knxnetip(p->data);
}

void SetupKNXnetIP(void)
{
#ifndef SNORT_RELOAD
	RegisterProprocessor("knxnetip", KNXnetIPInit);
#else
	RegisterPreprocessor("knxnetip", KNXnetIPInit, NULL, NULL, NULL, NULL);
#endif
	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: KNXnet/IP is setup...\n"););
}
