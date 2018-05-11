/*
 * knx_ui_snort.h
 *
 *  Created on: May 6, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */

#ifndef __KNX_USER_INTERFACE_SNORT__
#define __KNX_USER_INTERFACE_SNORT__

#include "snort.h"
#include "knx_ui_config.h"

#define KNX_UI_BACKGROUND_COLOR "\e[47m"
#define KNX_UI_FOREGROUND_COLOR "\e[30m"
#define KNX_UI_RESET_COLOR "\e[49m\e[39m"

int KNXnetIPCopyGlobalConf(KNXNETIP_CONF *config);
int KNXnetIPInitializeGlobalConfig(KNXNETIP_CONF *config, char *errstr, int errstrlen);
int KNXnetIPInitializeServerConfig(KNXNETIP_CONF *config, char *errstr, int errstrlen);
int KNXnetIPProcessConf(struct _SnortConfig *sc, KNXNETIP_CONF *config, char *errstr, int errstrlen);
int KNXnetIPPrintGlobalConf(KNXNETIP_CONF *config);
int KNXnetIPPrintServerConf(KNXNETIP_CONF *config);

#endif /* __KNX_USER_INTERFACE_SNORT__ */
