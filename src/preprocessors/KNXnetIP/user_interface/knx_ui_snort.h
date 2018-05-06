/*
 * knx_ui_snort.h
 *
 *  Created on: May 6, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */

#ifndef __KNX_USER_INTERFACE_SNORT__
#define __KNX_USER_INTERFACE_SNORT__

#include "knx_ui_config.h"

#include "snort.h"

int KNXnetIPInitializeGlobalConfig(KNXNETIP_CONF *config, char *ErrorString, int iErrStrLen);
int KNXnetIPProcessGlobalConf(KNXNETIP_CONF *GlobalConf, char *errstr, int errstrlen);
int KNXnetIPProcessUniqueServerConf(struct _SnortConfig *sc, KNXNETIP_CONF *GlobalConf, char *errstr, int errstrlen);
int KNXnetIPPrintGlobalConf(KNXNETIP_CONF *GlobalConf);
int KNXnetIPPrintServerConf(KNXNETIP_SERVER_CONF *ServerConf);

#endif /* __KNX_USER_INTERFACE_SNORT__ */
